"""
WaaaghGate — pipeline report generator.

Produces scan reports in multiple formats for CI/CD consumption:
  - JSON (machine-readable)
  - SARIF (GitHub / Azure DevOps code scanning)
  - Markdown (PR comments, artifacts)
"""

from __future__ import annotations

import enum
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity
from krumpa.waaaghgate.gate import GateResult

logger = logging.getLogger("krumpa.waaaghgate.reporter")


class ReportFormat(enum.Enum):
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    JUNIT = "junit"


class PipelineReporter:
    """
    Generate pipeline-friendly reports.

    Parameters
    ----------
    formats:
        Which report formats to produce.
    tool_name:
        Name embedded in SARIF reports.
    tool_version:
        Version embedded in SARIF reports.
    """

    def __init__(
        self,
        *,
        formats: Optional[List[ReportFormat]] = None,
        tool_name: str = "GateKrumpa",
        tool_version: str = "0.1.0",
    ) -> None:
        self.formats = formats or [ReportFormat.JSON]
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        findings: List[Finding],
        gate_result: Optional[GateResult] = None,
        ctx: Optional[ScanContext] = None,
    ) -> Dict[ReportFormat, str]:
        """Return a dict of format → rendered string."""
        reports: Dict[ReportFormat, str] = {}
        for fmt in self.formats:
            if fmt == ReportFormat.JSON:
                reports[fmt] = self._to_json(findings, gate_result, ctx)
            elif fmt == ReportFormat.SARIF:
                reports[fmt] = self._to_sarif(findings)
            elif fmt == ReportFormat.MARKDOWN:
                reports[fmt] = self._to_markdown(findings, gate_result)
            elif fmt == ReportFormat.JUNIT:
                reports[fmt] = self._to_junit(findings)
        return reports

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _to_json(
        self,
        findings: List[Finding],
        gate_result: Optional[GateResult],
        ctx: Optional[ScanContext],
    ) -> str:
        doc: Dict[str, Any] = {
            "tool": self.tool_name,
            "version": self.tool_version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [f.to_dict() for f in findings],
            "total": len(findings),
        }
        if gate_result:
            doc["gate"] = {
                "passed": gate_result.passed,
                "exit_code": gate_result.exit_code,
                "summary": gate_result.summary,
                "violations": [
                    {"severity": v.severity.value, "count": v.count, "threshold": v.threshold}
                    for v in gate_result.violations
                ],
                "warnings": gate_result.warnings,
            }
        if ctx:
            doc["scan"] = ctx.summary()
        return json.dumps(doc, indent=2, default=str)

    # ------------------------------------------------------------------
    # SARIF
    # ------------------------------------------------------------------

    _SEVERITY_TO_SARIF = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    def _to_sarif(self, findings: List[Finding]) -> str:
        results = []
        for f in findings:
            result: Dict[str, Any] = {
                "ruleId": f"CWE-{f.cwe}" if f.cwe else f.id,
                "level": self._SEVERITY_TO_SARIF.get(f.severity, "note"),
                "message": {"text": f.title},
            }
            if f.target:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target.url},
                    }
                }]
            results.append(result)

        sarif: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                    },
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2, default=str)

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def _to_markdown(
        self, findings: List[Finding], gate_result: Optional[GateResult],
    ) -> str:
        lines: List[str] = []
        lines.append(f"# {self.tool_name} Scan Report\n")

        if gate_result:
            status = "PASSED" if gate_result.passed else "FAILED"
            icon = "✅" if gate_result.passed else "❌"
            lines.append(f"**Gate**: {icon} {status}\n")
            if gate_result.violations:
                lines.append("### Violations\n")
                for v in gate_result.violations:
                    lines.append(f"- {v.message}")
                lines.append("")
            if gate_result.warnings:
                lines.append("### Warnings\n")
                for w in gate_result.warnings:
                    lines.append(f"- {w}")
                lines.append("")

        lines.append(f"**Total findings**: {len(findings)}\n")

        if findings:
            lines.append("| Severity | Title | Target | CWE |")
            lines.append("|----------|-------|--------|-----|")
            for f in findings:
                target = f.target.url if f.target else "—"
                cwe = f"CWE-{f.cwe}" if f.cwe else "—"
                lines.append(f"| {f.severity.value} | {f.title} | {target} | {cwe} |")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JUnit XML  (standard CI/CD format — parseable by Jenkins, GitHub
    # Actions, GitLab CI, Azure Pipelines, etc.)
    # ------------------------------------------------------------------

    def _to_junit(self, findings: List[Finding]) -> str:
        """Render findings as a JUnit XML test-suite.

        Each finding becomes a ``<testcase>`` with a ``<failure>`` element
        so CI systems correctly flag the build.  INFO-level findings are
        reported as passing test-cases.
        """
        import xml.etree.ElementTree as ET

        suite = ET.Element("testsuite")
        suite.set("name", self.tool_name)
        suite.set("tests", str(len(findings)))
        failures = sum(1 for f in findings if f.severity != Severity.INFO)
        suite.set("failures", str(failures))
        suite.set("errors", "0")
        suite.set("timestamp", datetime.now(timezone.utc).isoformat())

        for f in findings:
            tc = ET.SubElement(suite, "testcase")
            classname = f"CWE-{f.cwe}" if f.cwe else f.module or "unknown"
            tc.set("classname", classname)
            tc.set("name", f.title)

            if f.severity != Severity.INFO:
                fail_el = ET.SubElement(tc, "failure")
                fail_el.set("type", f.severity.value)
                fail_el.set("message", f.title)
                body_parts: List[str] = []
                if f.description:
                    body_parts.append(f.description)
                if f.evidence:
                    body_parts.append(f"Evidence: {f.evidence}")
                if f.target:
                    body_parts.append(f"Target: {f.target.method} {f.target.url}")
                if f.remediation:
                    body_parts.append(f"Remediation: {f.remediation}")
                fail_el.text = "\n".join(body_parts)

        tree = ET.ElementTree(suite)
        from io import StringIO
        buf = StringIO()
        tree.write(buf, encoding="unicode", xml_declaration=True)
        return buf.getvalue()
