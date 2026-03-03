"""
WaaaghGate — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from krumpa.core import BaseModule, Finding, ScanContext, Severity
from krumpa.waaaghgate.gate import GatePolicy, GateResult
from krumpa.waaaghgate.reporter import PipelineReporter, ReportFormat
from krumpa.waaaghgate.compliance import ComplianceMapper
from krumpa.waaaghgate.suppression import SuppressionManager
from krumpa.waaaghgate.html_report import HtmlReportGenerator
from krumpa.waaaghgate.diff_report import DiffReporter
from krumpa.waaaghgate.pr_annotator import PrAnnotator
from krumpa.waaaghgate.webhook_notifier import WebhookNotifier, WebhookConfig
from krumpa.waaaghgate.finding_lifecycle import FindingLifecycleManager
from krumpa.waaaghgate.trend_tracker import TrendTracker
from krumpa.waaaghgate.sla_enforcer import SlaEnforcer

logger = logging.getLogger("krumpa.waaaghgate")


class WaaaghGateModule(BaseModule):
    """CI/CD integration — quality gate + multi-format reporting."""

    name = "WaaaghGate"
    description = "CI/CD Integration — quality-gate policies and pipeline reporting"
    dependencies: List[str] = [
        "RedTeef", "BossKey", "WaaaghLogic", "OpenKrump",
    ]  # evaluates all findings — runs last

    def __init__(
        self,
        *,
        policy: Optional[GatePolicy] = None,
        reporter: Optional[PipelineReporter] = None,
        report_formats: Optional[List[ReportFormat]] = None,
        suppression_file: Optional[str] = None,
        project_root: Optional[str] = None,
        pr_platform: str = "github",
        webhooks: Optional[List[WebhookConfig]] = None,
        lifecycle_file: Optional[str] = None,
        history_file: Optional[str] = None,
        sla_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__()
        self._policy = policy or GatePolicy()
        self._reporter = reporter or PipelineReporter(
            formats=report_formats or [ReportFormat.JSON, ReportFormat.MARKDOWN],
        )
        self._compliance = ComplianceMapper()
        self._suppression = SuppressionManager(
            ignore_file=suppression_file,
        )
        self._html_report = HtmlReportGenerator()
        self._diff_reporter = DiffReporter()
        self._pr_annotator = PrAnnotator(platform=pr_platform)
        self._webhook = WebhookNotifier(webhooks=webhooks)
        self._lifecycle = FindingLifecycleManager(state_file=lifecycle_file)
        self._trend = TrendTracker(history_file=history_file)
        self._sla = SlaEnforcer(
            policy=None,  # uses defaults; override via sla_config
        )
        self._project_root = project_root
        self.gate_result: Optional[GateResult] = None
        self.reports: Dict[ReportFormat, str] = {}
        self.html_report: Optional[str] = None
        self.compliance_summary: Dict[str, Any] = {}
        self.pr_report: Optional[Any] = None
        self.lifecycle_result: Optional[Dict[str, List[str]]] = None
        self.sla_breaches: List[Finding] = []

    # ------------------------------------------------------------------
    # Module lifecycle
    # ------------------------------------------------------------------

    async def run(self, ctx: ScanContext) -> List[Finding]:
        """
        Evaluate the quality gate and generate reports.

        This module doesn't produce new security findings — it assesses
        existing ones and stores the gate result + reports.
        """
        all_findings = ctx.findings

        # 1. Load and apply suppression rules
        self._suppression.load(self._project_root)
        suppression_result = self._suppression.apply(all_findings)
        active_findings = suppression_result.active_findings
        if suppression_result.suppressed_count:
            logger.info(
                "Suppressed %d/%d findings",
                suppression_result.suppressed_count,
                suppression_result.original_count,
            )

        # 2. Evaluate gate policy (on active findings only)
        self.gate_result = self._policy.evaluate(active_findings)
        logger.info("Gate result: %s", self.gate_result.summary)

        # 3. Compliance mapping
        self.compliance_summary = {
            k: sorted(v)
            for k, v in self._compliance.summary(active_findings).items()
        }

        # 4. Generate standard reports (JSON, SARIF, Markdown, JUnit)
        self.reports = self._reporter.generate(
            active_findings,
            gate_result=self.gate_result,
            ctx=ctx,
        )
        for fmt, content in self.reports.items():
            logger.debug("Report [%s]: %d chars", fmt.value, len(content))

        # 5. HTML report
        duration = None
        if ctx.started_at and ctx.finished_at:
            duration = (ctx.finished_at - ctx.started_at).total_seconds()
        self.html_report = self._html_report.generate(
            active_findings, scan_duration=duration,
        )

        # 6. PR / MR annotations
        self.pr_report = self._pr_annotator.generate_report(active_findings)

        # 7. Finding lifecycle — track state transitions
        self.lifecycle_result = self._lifecycle.process_scan_results(active_findings)

        # 8. Trend tracking — record scan and compute metrics
        duration_val = None
        if ctx.started_at and ctx.finished_at:
            duration_val = (ctx.finished_at - ctx.started_at).total_seconds()
        scan_record = self._trend.record_scan(
            active_findings,
            gate_passed=self.gate_result.passed,
            duration=duration_val,
        )
        ctx.metadata["trend_direction"] = self._trend.trend_direction()
        ctx.metadata["trend_summary"] = self._trend.summary()

        # 9. SLA enforcement — check for overdue findings
        self.sla_breaches = self._sla.breach_findings(active_findings)
        if self.sla_breaches:
            logger.warning("SLA breaches: %d findings overdue", len(self.sla_breaches))
            # SLA breaches can optionally fail the gate
            if not self._sla.gate_check(active_findings):
                self.gate_result = self._policy.evaluate(
                    active_findings + self.sla_breaches,
                )

        # 10. Webhook notifications
        await self._webhook.notify(
            active_findings,
            gate_passed=self.gate_result.passed,
        )

        # 7. Store gate metadata in context for downstream use
        ctx.metadata["gate_passed"] = self.gate_result.passed
        ctx.metadata["gate_exit_code"] = self.gate_result.exit_code
        ctx.metadata["gate_summary"] = self.gate_result.summary
        ctx.metadata["compliance"] = self.compliance_summary
        ctx.metadata["suppressed_count"] = suppression_result.suppressed_count
        ctx.metadata["lifecycle"] = self.lifecycle_result
        ctx.metadata["sla_breaches"] = len(self.sla_breaches)

        return []  # no new findings
