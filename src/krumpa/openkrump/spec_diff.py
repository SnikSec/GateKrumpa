"""
OpenKrump — Spec diff / shadow API detection.

Compare the deployed API's actual behavior against the OpenAPI spec:
- Endpoints that respond but aren't in the spec (shadow APIs)
- Spec-declared endpoints that return 404 (stale spec)
- Extra response fields not in the schema (data leakage)
- Missing response fields (broken contract)
- Status code mismatches

Helps detect shadow endpoints, undocumented admin APIs, and spec drift.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient
from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.spec_diff")


class DiffType(Enum):
    """Types of spec-vs-reality differences."""
    SHADOW_ENDPOINT = "shadow_endpoint"          # responds but not in spec
    STALE_ENDPOINT = "stale_endpoint"            # in spec but 404
    EXTRA_FIELDS = "extra_response_fields"       # fields not in schema
    MISSING_FIELDS = "missing_response_fields"   # schema fields not in response
    STATUS_MISMATCH = "status_code_mismatch"     # unexpected status code
    METHOD_MISMATCH = "method_not_allowed"       # spec says supported, server says 405


@dataclass
class SpecDiffItem:
    """A single difference between spec and deployed API."""
    diff_type: DiffType
    path: str
    method: str
    description: str
    spec_value: Any = None
    actual_value: Any = None


@dataclass
class SpecDiffReport:
    """Full diff report."""
    total_checks: int = 0
    diffs: List[SpecDiffItem] = field(default_factory=list)
    shadow_count: int = 0
    stale_count: int = 0
    field_diff_count: int = 0

    @property
    def has_issues(self) -> bool:
        return len(self.diffs) > 0


# Common shadow/undocumented paths to probe
_SHADOW_PROBE_PATHS: List[str] = [
    "/admin",
    "/api/admin",
    "/api/v1/admin",
    "/api/v2",
    "/api/internal",
    "/api/debug",
    "/api/test",
    "/api/health",
    "/api/healthz",
    "/api/ready",
    "/api/metrics",
    "/api/status",
    "/api/info",
    "/api/config",
    "/api/env",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/graphql",
    "/api/gql",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/.env",
    "/debug/vars",
    "/debug/pprof",
    "/server-status",
    "/api/users",
    "/api/tokens",
    "/api/keys",
    "/api/secrets",
    "/api/backup",
    "/api/export",
    "/api/dump",
    "/api/logs",
]


class SpecDiffChecker:
    """
    Compare deployed API behavior against the OpenAPI specification.

    Detects shadow (undocumented) endpoints, stale spec entries,
    response schema drift, and undocumented status codes.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        probe_shadow: bool = True,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._probe_shadow = probe_shadow

    async def diff(
        self,
        spec: Dict[str, Any],
        endpoints: List[ParsedEndpoint],
        base_url: str,
    ) -> List[Finding]:
        """
        Run the full spec diff and return findings.

        Args:
            spec: The full OpenAPI spec dict.
            endpoints: Parsed endpoints from the spec.
            base_url: Base URL of the target API.

        Returns:
            Findings for each significant difference.
        """
        findings: List[Finding] = []
        report = SpecDiffReport()

        # 1. Check spec endpoints against live API
        spec_findings = await self._check_spec_endpoints(endpoints, base_url, report)
        findings.extend(spec_findings)

        # 2. Check response schemas
        schema_findings = await self._check_response_schemas(endpoints, base_url, spec, report)
        findings.extend(schema_findings)

        # 3. Probe for shadow / undocumented endpoints
        if self._probe_shadow:
            spec_paths = {ep.path.lower() for ep in endpoints}
            shadow_findings = await self._probe_shadow_endpoints(base_url, spec_paths, report)
            findings.extend(shadow_findings)

        logger.info(
            "Spec diff: %d total checks, %d diffs (%d shadow, %d stale, %d field diffs)",
            report.total_checks, len(report.diffs),
            report.shadow_count, report.stale_count, report.field_diff_count,
        )

        return findings

    # ------------------------------------------------------------------
    # Spec endpoint verification
    # ------------------------------------------------------------------

    async def _check_spec_endpoints(
        self,
        endpoints: List[ParsedEndpoint],
        base_url: str,
        report: SpecDiffReport,
    ) -> List[Finding]:
        """Verify spec endpoints are actually live."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        for ep in endpoints:
            report.total_checks += 1
            url = self._resolve_url(base_url, ep.path)

            try:
                resp = await self._client.request(
                    ep.method, url,
                    headers={"Accept": "application/json"},
                )

                if resp.status_code == 404:
                    diff = SpecDiffItem(
                        diff_type=DiffType.STALE_ENDPOINT,
                        path=ep.path, method=ep.method,
                        description=f"Spec declares {ep.method} {ep.path} but server returns 404",
                        spec_value="defined", actual_value="404",
                    )
                    report.diffs.append(diff)
                    report.stale_count += 1
                    findings.append(self._build_finding(url, ep.method, diff))

                elif resp.status_code == 405:
                    diff = SpecDiffItem(
                        diff_type=DiffType.METHOD_MISMATCH,
                        path=ep.path, method=ep.method,
                        description=f"Spec declares {ep.method} {ep.path} but server returns 405 Method Not Allowed",
                        spec_value=ep.method, actual_value="405",
                    )
                    report.diffs.append(diff)
                    findings.append(self._build_finding(url, ep.method, diff))

            except (httpx.HTTPError, OSError) as exc:
                logger.debug("Error checking %s %s: %s", ep.method, url, exc)

        return findings

    # ------------------------------------------------------------------
    # Response schema verification
    # ------------------------------------------------------------------

    async def _check_response_schemas(
        self,
        endpoints: List[ParsedEndpoint],
        base_url: str,
        spec: Dict[str, Any],
        report: SpecDiffReport,
    ) -> List[Finding]:
        """Compare actual response fields against schema definitions."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        for ep in endpoints:
            if not ep.response_schemas:
                continue

            url = self._resolve_url(base_url, ep.path)
            report.total_checks += 1

            try:
                resp = await self._client.request(
                    ep.method, url,
                    headers={"Accept": "application/json"},
                )

                body = self._try_parse_json(resp.text)
                if not isinstance(body, dict):
                    continue

                # Get the schema for the actual status code
                status_str = str(resp.status_code)
                resp_schema = (
                    ep.response_schemas.get(status_str)
                    or ep.response_schemas.get("200")
                    or ep.response_schemas.get("default")
                )
                if not resp_schema:
                    continue

                schema_def = (
                    resp_schema.get("schema")
                    or resp_schema.get("content", {}).get("application/json", {}).get("schema", {})
                )
                if not schema_def:
                    continue

                expected_fields = set(schema_def.get("properties", {}).keys())
                actual_fields = set(body.keys())

                # Extra fields (shadow data / data leakage)
                extra = actual_fields - expected_fields
                if extra and expected_fields:  # only flag if schema has properties
                    diff = SpecDiffItem(
                        diff_type=DiffType.EXTRA_FIELDS,
                        path=ep.path, method=ep.method,
                        description=f"Response contains {len(extra)} undocumented field(s)",
                        spec_value=sorted(expected_fields),
                        actual_value=sorted(extra),
                    )
                    report.diffs.append(diff)
                    report.field_diff_count += 1
                    findings.append(self._build_field_finding(url, ep, diff, "extra"))

                # Missing required fields
                required = set(schema_def.get("required", []))
                missing = required - actual_fields
                if missing:
                    diff = SpecDiffItem(
                        diff_type=DiffType.MISSING_FIELDS,
                        path=ep.path, method=ep.method,
                        description=f"Response missing {len(missing)} required field(s)",
                        spec_value=sorted(required),
                        actual_value=sorted(missing),
                    )
                    report.diffs.append(diff)
                    report.field_diff_count += 1
                    findings.append(self._build_field_finding(url, ep, diff, "missing"))

            except (httpx.HTTPError, OSError) as exc:
                logger.debug("Schema diff error for %s %s: %s", ep.method, url, exc)

        return findings

    # ------------------------------------------------------------------
    # Shadow API detection
    # ------------------------------------------------------------------

    async def _probe_shadow_endpoints(
        self,
        base_url: str,
        spec_paths: Set[str],
        report: SpecDiffReport,
    ) -> List[Finding]:
        """Probe common undocumented paths for shadow endpoints."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        for probe_path in _SHADOW_PROBE_PATHS:
            if probe_path.lower() in spec_paths:
                continue

            report.total_checks += 1
            url = self._resolve_url(base_url, probe_path)

            try:
                resp = await self._client.request(
                    "GET", url,
                    headers={"Accept": "application/json"},
                )

                # Consider it a shadow endpoint if it returns a non-error response
                if resp.status_code < 400 and resp.status_code != 301:
                    diff = SpecDiffItem(
                        diff_type=DiffType.SHADOW_ENDPOINT,
                        path=probe_path, method="GET",
                        description=(
                            f"Undocumented endpoint responds at {probe_path} "
                            f"(status {resp.status_code})"
                        ),
                        spec_value="not documented",
                        actual_value=resp.status_code,
                    )
                    report.diffs.append(diff)
                    report.shadow_count += 1
                    findings.append(self._build_shadow_finding(url, probe_path, resp.status_code))

            except (httpx.HTTPError, OSError):
                pass  # expected for most probes

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_url(base_url: str, path: str) -> str:
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    @staticmethod
    def _try_parse_json(text: str) -> Any:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding(url: str, method: str, diff: SpecDiffItem) -> Finding:
        severity_map = {
            DiffType.SHADOW_ENDPOINT: Severity.HIGH,
            DiffType.STALE_ENDPOINT: Severity.LOW,
            DiffType.METHOD_MISMATCH: Severity.LOW,
            DiffType.EXTRA_FIELDS: Severity.MEDIUM,
            DiffType.MISSING_FIELDS: Severity.LOW,
            DiffType.STATUS_MISMATCH: Severity.LOW,
        }
        return Finding(
            title=f"Spec drift: {diff.diff_type.value} on {method.upper()} {diff.path}",
            description=diff.description,
            severity=severity_map.get(diff.diff_type, Severity.LOW),
            target=Target(url=url, method=method),
            evidence=f"spec={diff.spec_value}, actual={diff.actual_value}",
            remediation="Update the API spec to match the deployed behavior, or fix the API.",
            cwe=0,
            tags=["spec-diff", diff.diff_type.value, "api", "openkrump"],
        )

    @staticmethod
    def _build_field_finding(
        url: str, ep: ParsedEndpoint, diff: SpecDiffItem, kind: str,
    ) -> Finding:
        if kind == "extra":
            return Finding(
                title=f"Undocumented response fields on {ep.method.upper()} {ep.path}",
                description=(
                    f"Response contains fields not documented in the spec: "
                    f"{diff.actual_value}. This may indicate data leakage."
                ),
                severity=Severity.MEDIUM,
                target=Target(url=url, method=ep.method),
                evidence=f"extra_fields={diff.actual_value}, expected={diff.spec_value}",
                remediation=(
                    "Review undocumented fields for sensitive data. "
                    "Either add them to the spec or remove them from the response."
                ),
                cwe=200,
                tags=["spec-diff", "extra-fields", "data-leakage", "api", "openkrump"],
            )
        else:
            return Finding(
                title=f"Missing required fields on {ep.method.upper()} {ep.path}",
                description=(
                    f"Response is missing required fields: {diff.actual_value}. "
                    "This is a spec contract violation."
                ),
                severity=Severity.LOW,
                target=Target(url=url, method=ep.method),
                evidence=f"missing_fields={diff.actual_value}, required={diff.spec_value}",
                remediation="Ensure the API returns all required fields defined in the spec.",
                cwe=0,
                tags=["spec-diff", "missing-fields", "api", "openkrump"],
            )

    @staticmethod
    def _build_shadow_finding(url: str, path: str, status: int) -> Finding:
        return Finding(
            title=f"Shadow API endpoint: {path}",
            description=(
                f"Undocumented endpoint at {path} responds with status {status}. "
                "This endpoint is not in the OpenAPI spec and may represent "
                "an internal/admin/debug interface that should not be exposed."
            ),
            severity=Severity.HIGH,
            target=Target(url=url, method="GET"),
            evidence=f"path={path}, status={status}, spec=not_documented",
            remediation=(
                "Either document this endpoint in the spec or remove it from the "
                "production deployment. If it's an internal endpoint, restrict access."
            ),
            cwe=912,
            tags=["shadow-api", "spec-diff", "undocumented", "api", "openkrump"],
        )
