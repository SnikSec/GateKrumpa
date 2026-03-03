"""
WaaaghLogic — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from krumpa.core import BaseModule, Finding, ScanContext, Target
from krumpa.waaaghlogic.flow_analyzer import FlowAnalyzer, WorkflowStep
from krumpa.waaaghlogic.idempotency_checker import IdempotencyChecker
from krumpa.waaaghlogic.mass_assignment import MassAssignmentTester
from krumpa.waaaghlogic.file_upload import FileUploadTester
from krumpa.waaaghlogic.privilege_escalation import PrivilegeEscalationTester
from krumpa.waaaghlogic.pagination import PaginationTester
from krumpa.waaaghlogic.data_validation import DataValidationTester
from krumpa.waaaghlogic.numeric_precision import NumericPrecisionTester
from krumpa.waaaghlogic.input_length_boundary import InputLengthBoundaryTester
from krumpa.waaaghlogic.bulk_operation_abuse import BulkOperationTester
from krumpa.waaaghlogic.state_machine import StateMachineTester
from krumpa.waaaghlogic.graphql_logic import GraphqlLogicTester
from krumpa.waaaghlogic.workflow_integrity import WorkflowIntegrityTester
from krumpa.waaaghlogic.currency_rounding import CurrencyRoundingTester

logger = logging.getLogger("krumpa.waaaghlogic")


class WaaaghLogicModule(BaseModule):
    """Business logic testing — workflow analysis, tampering, race conditions."""

    name = "WaaaghLogic"
    description = "Business Logic Testing — workflow flaws, parameter tampering, race conditions"
    dependencies: List[str] = ["SneakyGits"]  # needs discovered targets

    def __init__(
        self,
        *,
        workflows: Optional[List[List[WorkflowStep]]] = None,
        idempotency_targets: Optional[List[Dict[str, Any]]] = None,
        concurrency: int = 5,
    ) -> None:
        super().__init__()
        self._flow_analyzer = FlowAnalyzer()
        self._idempotency_checker = IdempotencyChecker(concurrency=concurrency)
        self._mass_assignment = MassAssignmentTester()
        self._file_upload = FileUploadTester()
        self._privesc = PrivilegeEscalationTester()
        self._pagination = PaginationTester()
        self._data_validation = DataValidationTester()
        self._numeric_precision = NumericPrecisionTester()
        self._input_length = InputLengthBoundaryTester()
        self._bulk_ops = BulkOperationTester()
        self._state_machine = StateMachineTester()
        self._graphql_logic = GraphqlLogicTester()
        self._workflow_integrity = WorkflowIntegrityTester()
        self._currency_rounding = CurrencyRoundingTester()
        self._workflows = workflows or []
        self._idempotency_targets = idempotency_targets or []

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client into sub-components."""
        if ctx.http_client:
            self._flow_analyzer._client = ctx.http_client
            self._flow_analyzer._owns_client = False
            self._idempotency_checker._client = ctx.http_client
            self._idempotency_checker._owns_client = False
            self._mass_assignment._client = ctx.http_client
            self._mass_assignment._owns_client = False
            self._file_upload._client = ctx.http_client
            self._file_upload._owns_client = False
            self._privesc._client = ctx.http_client
            self._privesc._owns_client = False
            self._pagination._client = ctx.http_client
            self._pagination._owns_client = False
            self._data_validation._client = ctx.http_client
            self._data_validation._owns_client = False
            self._numeric_precision._client = ctx.http_client
            self._numeric_precision._owns_client = False
            self._input_length._client = ctx.http_client
            self._input_length._owns_client = False
            self._bulk_ops._client = ctx.http_client
            self._bulk_ops._owns_client = False
            self._state_machine._client = ctx.http_client
            self._state_machine._owns_client = False
            self._graphql_logic._client = ctx.http_client
            self._graphql_logic._owns_client = False
            self._workflow_integrity._client = ctx.http_client
            self._workflow_integrity._owns_client = False
            self._currency_rounding._client = ctx.http_client
            self._currency_rounding._owns_client = False

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # --- Workflow analysis -------------------------------------------
        for workflow in self._workflows:
            if not workflow:
                continue
            target = self._resolve_target(workflow[0].url, ctx)
            logger.info("Testing workflow (%d steps) starting at %s", len(workflow), workflow[0].url)
            wf_findings = await self._flow_analyzer.test_workflow(workflow, target)
            findings.extend(wf_findings)

        # --- Idempotency / race-condition checks -------------------------
        for spec in self._idempotency_targets:
            url = spec.get("url", "")
            if not url:
                continue
            target = self._resolve_target(url, ctx)
            logger.info("Testing idempotency on %s", url)
            idem_findings = await self._idempotency_checker.check(
                url,
                target,
                method=spec.get("method", "POST"),
                body=spec.get("body"),
                expected_status=spec.get("expected_status", 200),
            )
            findings.extend(idem_findings)

        # --- Auto-detect state-changing endpoints from context -----------
        auto_targets = self._detect_state_changing(ctx)
        for url, method in auto_targets:
            target = self._resolve_target(url, ctx)
            logger.info("Auto-testing idempotency on %s %s", method, url)
            idem_findings = await self._idempotency_checker.check(
                url, target, method=method,
            )
            findings.extend(idem_findings)

        # --- Mass assignment testing on state-changing endpoints ----------
        for url, method in auto_targets:
            if method.upper() in ("POST", "PUT", "PATCH"):
                target = self._resolve_target(url, ctx)
                logger.info("Testing mass assignment on %s %s", method, url)
                ma_findings = await self._mass_assignment.test(target)
                findings.extend(ma_findings)

        # --- File upload testing on POST endpoints -------------------------
        upload_targets = [t for t in ctx.targets if t.method.upper() == "POST"]
        for target in upload_targets:
            if any(h in target.url.lower() for h in ("/upload", "/file", "/attach", "/import", "/media")):
                logger.info("Testing file upload on %s", target.url)
                upload_findings = await self._file_upload.test(target)
                findings.extend(upload_findings)

        # --- Privilege escalation testing ----------------------------------
        for target in ctx.targets:
            privesc_findings = await self._privesc.test_horizontal(target)
            findings.extend(privesc_findings)
            idor_findings = await self._privesc.test_idor(target)
            findings.extend(idor_findings)

        # --- Pagination abuse testing on GET endpoints with lists -----------
        list_targets = [t for t in ctx.targets if t.method.upper() == "GET"]
        for target in list_targets:
            if any(h in target.url.lower() for h in ("/list", "/search", "/users", "/items", "/api/")):
                logger.info("Testing pagination on %s", target.url)
                page_findings = await self._pagination.test(target)
                findings.extend(page_findings)

        # --- Data validation bypass on state-changing endpoints ------------
        for url, method in auto_targets:
            target = self._resolve_target(url, ctx)
            logger.info("Testing data validation on %s %s", method, url)
            dv_findings = await self._data_validation.test(target)
            findings.extend(dv_findings)

        # --- Numeric precision abuse on state-changing endpoints -----------
        for url, method in auto_targets:
            if method.upper() in ("POST", "PUT", "PATCH"):
                target = self._resolve_target(url, ctx)
                logger.info("Testing numeric precision on %s %s", method, url)
                np_findings = await self._numeric_precision.test(target)
                findings.extend(np_findings)

        # --- Input length boundary testing on state-changing endpoints -----
        for url, method in auto_targets:
            target = self._resolve_target(url, ctx)
            logger.info("Testing input length boundaries on %s %s", method, url)
            il_findings = await self._input_length.test(target)
            findings.extend(il_findings)

        # --- Bulk operation abuse on batch/bulk endpoints ------------------
        bulk_targets = [t for t in ctx.targets if any(
            h in t.url.lower() for h in ("/bulk", "/batch", "/mass", "/all", "/export")
        )]
        for target in bulk_targets:
            logger.info("Testing bulk operation abuse on %s", target.url)
            bulk_findings = await self._bulk_ops.test(target)
            findings.extend(bulk_findings)

        # --- State machine testing on state-changing endpoints -------------
        for url, method in auto_targets:
            if method.upper() in ("POST", "PUT", "PATCH"):
                target = self._resolve_target(url, ctx)
                logger.info("Testing state machine transitions on %s", target.url)
                sm_findings = await self._state_machine.test(target)
                findings.extend(sm_findings)

        # --- GraphQL-specific logic on GraphQL endpoints -------------------
        graphql_targets = [t for t in ctx.targets if any(
            h in t.url.lower() for h in ("/graphql", "/gql", "/query")
        )]
        for target in graphql_targets:
            logger.info("Testing GraphQL logic on %s", target.url)
            gql_findings = await self._graphql_logic.test(target)
            findings.extend(gql_findings)

        # --- Workflow integrity (payment-specific) -------------------------
        for target in ctx.targets:
            if any(h in target.url.lower() for h in (
                "/checkout", "/payment", "/pay", "/order", "/cart",
                "/purchase", "/subscribe", "/billing",
            )):
                logger.info("Testing workflow integrity on %s", target.url)
                wi_findings = await self._workflow_integrity.analyze(target)
                findings.extend(wi_findings)

        # --- Currency rounding exploitation --------------------------------
        for target in ctx.targets:
            if any(h in target.url.lower() for h in (
                "/price", "/amount", "/total", "/order", "/checkout",
                "/payment", "/cart", "/invoice", "/billing",
            )):
                logger.info("Testing currency rounding on %s", target.url)
                cr_findings = await self._currency_rounding.analyze(target)
                findings.extend(cr_findings)

        for f in findings:
            self.add_finding(f)

        logger.info("WaaaghLogic complete — %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target(url: str, ctx: ScanContext) -> Target:
        for t in ctx.targets:
            if t.url == url:
                return t
        return Target(url=url)

    @staticmethod
    def _detect_state_changing(ctx: ScanContext) -> List[tuple]:
        """
        Heuristic: pick targets whose metadata or method suggest
        state-changing operations worth testing.
        """
        results: List[tuple] = []
        seen = set()
        state_methods = ("POST", "PUT", "PATCH", "DELETE")

        for t in ctx.targets:
            if t.method.upper() in state_methods and t.url not in seen:
                seen.add(t.url)
                results.append((t.url, t.method))

        return results
