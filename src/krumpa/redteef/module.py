"""
RedTeef — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from krumpa.core import BaseModule, Finding, ScanContext, Severity, Target
from krumpa.core.http_client import HttpClient
from krumpa.redteef.confirmer import Confirmer, ConfirmationResult, ConfirmationVerdict
from krumpa.redteef.payload_builder import PayloadBuilder, ProofPayload
from krumpa.redteef.blind_sqli import BlindSqliConfirmer
from krumpa.redteef.env_payloads import EnvironmentPayloadSelector
from krumpa.redteef.error_sqli import ErrorSqliConfirmer
from krumpa.redteef.path_traversal_confirmer import PathTraversalConfirmer
from krumpa.redteef.open_redirect_confirmer import OpenRedirectConfirmer
from krumpa.redteef.blind_xss_confirmer import BlindXssConfirmer
from krumpa.redteef.ssrf_confirmer import SsrfConfirmer
from krumpa.redteef.xxe_confirmer import XxeConfirmer
from krumpa.redteef.evidence_scoring import EvidenceScorer
from krumpa.redteef.deserialization_confirmer import DeserializationConfirmer
from krumpa.redteef.polyglot_payloads import PolyglotPayloadTester
from krumpa.redteef.regression_canaries import RegressionCanaryChecker
from krumpa.redteef.exploit_chains import ExploitChainBuilder

logger = logging.getLogger("krumpa.redteef")


class RedTeefModule(BaseModule):
    """Exploit confirmation — validates fuzzer/scanner findings with safe PoCs."""

    name = "RedTeef"
    description = "Exploit Confirmation — safe PoC validation to reduce false positives"
    dependencies: List[str] = ["GrotAssault"]  # needs fuzzer findings to confirm

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        extra_canaries: Optional[Dict[str, List[ProofPayload]]] = None,
        confirmation_threshold: float = 0.5,
    ) -> None:
        super().__init__()
        self._explicit_client = http_client is not None
        self._builder = PayloadBuilder(extra_canaries=extra_canaries)
        self._confirmer = Confirmer(
            http_client=http_client,
            confirmation_threshold=confirmation_threshold,
        )
        self._blind_sqli = BlindSqliConfirmer(http_client=http_client)
        self._error_sqli = ErrorSqliConfirmer(http_client=http_client)
        self._env_selector = EnvironmentPayloadSelector()
        self._path_traversal = PathTraversalConfirmer(http_client=http_client)
        self._open_redirect = OpenRedirectConfirmer(http_client=http_client)
        self._blind_xss = BlindXssConfirmer(http_client=http_client)
        self._ssrf = SsrfConfirmer(http_client=http_client)
        self._xxe = XxeConfirmer(http_client=http_client)
        self._evidence_scorer = EvidenceScorer()
        self._deser_confirmer = DeserializationConfirmer(http_client=http_client)
        self._polyglot = PolyglotPayloadTester(http_client=http_client)
        self._regression = RegressionCanaryChecker(http_client=http_client)
        self._exploit_chains = ExploitChainBuilder()

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client into confirmer if no explicit client."""
        if ctx.http_client and not self._explicit_client:
            self._confirmer._client = ctx.http_client
            self._confirmer._owns_client = False
            self._blind_sqli._client = ctx.http_client
            self._blind_sqli._owns_client = False
            self._error_sqli._client = ctx.http_client
            self._error_sqli._owns_client = False
            self._path_traversal._client = ctx.http_client
            self._path_traversal._owns_client = False
            self._open_redirect._client = ctx.http_client
            self._open_redirect._owns_client = False
            self._blind_xss._client = ctx.http_client
            self._blind_xss._owns_client = False
            self._ssrf._client = ctx.http_client
            self._ssrf._owns_client = False
            self._xxe._client = ctx.http_client
            self._xxe._owns_client = False
            self._deser_confirmer._client = ctx.http_client
            self._deser_confirmer._owns_client = False
            self._polyglot._client = ctx.http_client
            self._polyglot._owns_client = False
            self._regression._client = ctx.http_client
            self._regression._owns_client = False
            self._exploit_chains._client = ctx.http_client
            self._exploit_chains._owns_client = False

    # ------------------------------------------------------------------
    # Module lifecycle
    # ------------------------------------------------------------------

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # Work through existing findings that might be confirmable
        candidates = self._select_candidates(ctx)
        if not candidates:
            logger.info("RedTeef: no confirmable findings in context")
            return findings

        # Detect environment for smarter payload selection
        first_target = ctx.targets[0] if ctx.targets else Target(url="https://unknown")
        env_profile = self._env_selector.detect_environment(ctx, first_target)
        if env_profile and (env_profile.databases or env_profile.frameworks):
            logger.info(
                "Detected environment: db=%s, framework=%s",
                ", ".join(env_profile.databases) or "unknown",
                ", ".join(env_profile.frameworks) or "unknown",
            )

        for finding in candidates:
            target = self._resolve_target(finding, ctx)
            vuln_type = self._builder.infer_vuln_type(
                finding.tags, finding.title,
            )
            if not vuln_type:
                logger.debug("Cannot infer vuln_type for finding %s", finding.id)
                continue

            inject_field = self._infer_field(finding)
            payloads = self._builder.build(
                vuln_type,
                inject_field=inject_field,
                http_method=target.method,
            )
            if not payloads:
                continue

            logger.info(
                "Confirming finding %s (type=%s) with %d payloads",
                finding.id, vuln_type, len(payloads),
            )

            result = await self._confirmer.confirm(finding, payloads, target)

            if result.confirmed:
                enriched = self._promote_finding(finding, result)
                findings.append(enriched)
            elif result.likely:
                enriched = self._promote_finding(finding, result, likely=True)
                findings.append(enriched)
            else:
                logger.info("Finding %s NOT confirmed", finding.id)

            # Blind SQLi confirmation for SQL-injection findings
            if vuln_type == "sqli" and not result.confirmed:
                blind_findings = await self._blind_sqli.confirm(
                    target, inject_field=self._infer_field(finding),
                )
                findings.extend(blind_findings)

                # Error-based SQLi confirmation as additional check
                error_findings = await self._error_sqli.confirm(
                    target, inject_field=self._infer_field(finding),
                )
                findings.extend(error_findings)

            # Path traversal confirmation
            if vuln_type in ("path-traversal", "lfi", "file-inclusion"):
                pt_findings = await self._path_traversal.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(pt_findings)

            # Open redirect confirmation
            if vuln_type in ("open-redirect", "redirect"):
                or_findings = await self._open_redirect.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(or_findings)

            # Blind XSS confirmation
            if vuln_type in ("xss", "stored-xss", "blind-xss"):
                xss_findings = await self._blind_xss.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(xss_findings)

            # SSRF confirmation
            if vuln_type in ("ssrf", "server-side-request-forgery"):
                ssrf_findings = await self._ssrf.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(ssrf_findings)

            # XXE confirmation
            if vuln_type in ("xxe", "xml-external-entity"):
                xxe_findings = await self._xxe.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(xxe_findings)

            # Deserialization confirmation
            if vuln_type in ("deserialization", "insecure-deserialization"):
                deser_findings = await self._deser_confirmer.confirm(
                    target, inject_field=inject_field,
                )
                findings.extend(deser_findings)

            # Polyglot payload testing (covers multiple vuln classes)
            if not result.confirmed:
                poly_findings = await self._polyglot.test(
                    target, inject_field=inject_field,
                    vuln_classes=[vuln_type],
                )
                findings.extend(poly_findings)

        # --- Regression canary checks — re-confirm previous findings ----
        regression_findings = await self._regression.reconfirm_all()
        findings.extend(regression_findings)

        # --- Score and rank all findings by evidence quality ---------------
        scored = self._evidence_scorer.batch_score(findings)
        logger.info(
            "Evidence scoring: %d findings scored, %d above threshold",
            len(findings), len(scored),
        )

        # --- Multi-step exploit chain analysis ----------------------------
        if ctx.targets:
            first_target = ctx.targets[0]
            chain_findings = await self._exploit_chains.analyze(
                first_target, findings + ctx.findings,
            )
            findings.extend(chain_findings)

        for f in findings:
            self.add_finding(f)

        logger.info("RedTeef complete — %d confirmed findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Candidate selection
    # ------------------------------------------------------------------

    @staticmethod
    def _select_candidates(ctx: ScanContext) -> List[Finding]:
        """
        Pick findings worth attempting to confirm. We skip INFO-level
        and findings already tagged as confirmed.
        """
        return [
            f for f in ctx.findings
            if f.severity != Severity.INFO and "confirmed" not in f.tags
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target(finding: Finding, ctx: ScanContext) -> Target:
        if finding.target:
            return finding.target
        if ctx.targets:
            return ctx.targets[0]
        return Target(url="https://unknown")

    @staticmethod
    def _infer_field(finding: Finding) -> str:
        """Try to extract the field name from the finding evidence / title."""
        # Look for patterns like "field 'username'" or "field 'q'"
        import re
        m = re.search(r"field\s+'([^']+)'", finding.evidence or finding.title)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _promote_finding(
        finding: Finding,
        result: ConfirmationResult,
        *,
        likely: bool = False,
    ) -> Finding:
        """Create an enriched copy of the original finding."""
        label = "confirmed" if not likely else "likely-confirmed"
        new_tags = list(finding.tags) + [label, "redteef"]
        new_evidence = finding.evidence
        if result.response_snippets:
            new_evidence += f"\n--- PoC evidence ---\n" + "\n".join(result.response_snippets)
        if result.notes:
            new_evidence += f"\nNotes: {result.notes}"

        return Finding(
            title=f"[{label.upper()}] {finding.title}",
            description=finding.description,
            severity=finding.severity if not likely else _lower_severity(finding.severity),
            target=finding.target,
            evidence=new_evidence,
            remediation=finding.remediation,
            cwe=finding.cwe,
            tags=new_tags,
        )


def _lower_severity(sev: Severity) -> Severity:
    """Drop severity by one level for 'likely' findings."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(sev)
    return order[max(0, idx - 1)]
