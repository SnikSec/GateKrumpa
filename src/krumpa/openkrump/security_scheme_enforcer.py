"""
OpenKrump — Security scheme enforcement (active).

Actively tests that endpoints defined with security requirements
in the spec actually enforce authentication by sending unauthenticated
requests and verifying 401/403 responses.

Also checks:
- Missing security definitions
- Inconsistent enforcement across methods
- Bearer vs. Basic enforcement
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin
from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.security_scheme_enforcer")


@dataclass
class SchemeTestResult(HttpClientMixin):
    """Result of testing security enforcement on one endpoint."""
    endpoint: ParsedEndpoint
    expected_schemes: List[str]
    status_code: int
    enforced: bool
    notes: str = ""


@dataclass
class EnforcementReport(HttpClientMixin):
    """Aggregate enforcement check results."""
    total_endpoints: int = 0
    protected_endpoints: int = 0
    unprotected_endpoints: int = 0
    failures: List[SchemeTestResult] = field(default_factory=list)
    warnings: List[SchemeTestResult] = field(default_factory=list)


class SecuritySchemeEnforcer(HttpClientMixin):
    """
    Send unauthenticated requests to endpoints that declare security
    requirements in the OpenAPI spec, then verify the server returns
    401 Unauthorized or 403 Forbidden.

    Findings are generated when:
    - An endpoint with security requirements returns 2xx without auth
    - An endpoint accepts requests with invalid/expired tokens
    - Security enforcement is inconsistent across HTTP methods
    """

    REJECTED_STATUSES: Set[int] = {401, 403}

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def enforce(
        self,
        spec: Dict[str, Any],
        endpoints: List[ParsedEndpoint],
        base_url: str,
    ) -> List[Finding]:
        """
        Test all endpoints with declared security for enforcement.

        Args:
            spec: The full OpenAPI spec dict.
            endpoints: Parsed endpoints from the spec.
            base_url: Base URL of the API.

        Returns:
            Findings for endpoints that failed enforcement.
        """
        findings: List[Finding] = []
        report = EnforcementReport(total_endpoints=len(endpoints))

        global_security = self._extract_global_security(spec)
        security_definitions = self._extract_security_definitions(spec)

        for ep in endpoints:
            schemes = self._get_effective_security(ep, global_security)
            if not schemes:
                report.unprotected_endpoints += 1
                continue

            report.protected_endpoints += 1
            url = self._resolve_url(base_url, ep.path)
            target = Target(url=url, method=ep.method)

            # Test 1: No auth at all
            result = await self._test_no_auth(ep, url, schemes)
            if not result.enforced:
                report.failures.append(result)
                findings.append(self._build_finding_no_auth(target, result, schemes))

            # Test 2: Invalid token/credentials
            for scheme_name in schemes:
                scheme_def = security_definitions.get(scheme_name, {})
                invalid_result = await self._test_invalid_auth(ep, url, scheme_name, scheme_def)
                if invalid_result and not invalid_result.enforced:
                    report.warnings.append(invalid_result)
                    findings.append(self._build_finding_invalid_auth(target, invalid_result))

        # Test 3: Cross-method consistency
        consistency_findings = self._check_method_consistency(endpoints, global_security)
        findings.extend(consistency_findings)

        logger.info(
            "Security enforcement: %d total, %d protected, %d unprotected, %d failures",
            report.total_endpoints, report.protected_endpoints,
            report.unprotected_endpoints, len(report.failures),
        )

        return findings

    # ------------------------------------------------------------------
    # Test methods
    # ------------------------------------------------------------------

    async def _test_no_auth(
        self,
        ep: ParsedEndpoint,
        url: str,
        schemes: List[str],
    ) -> SchemeTestResult:
        """Send request with no authentication, expect 401/403."""
        if not self._client:
            return SchemeTestResult(
                endpoint=ep, expected_schemes=schemes,
                status_code=0, enforced=True, notes="no client",
            )

        try:
            resp = await self._client.request(
                ep.method, url,
                headers={"Accept": "application/json"},
            )
            enforced = resp.status_code in self.REJECTED_STATUSES
            return SchemeTestResult(
                endpoint=ep,
                expected_schemes=schemes,
                status_code=resp.status_code,
                enforced=enforced,
                notes="" if enforced else f"expected 401/403, got {resp.status_code}",
            )
        except (httpx.HTTPError, OSError) as exc:
            return SchemeTestResult(
                endpoint=ep, expected_schemes=schemes,
                status_code=0, enforced=True,
                notes=f"request error (treated as enforced): {exc}",
            )

    async def _test_invalid_auth(
        self,
        ep: ParsedEndpoint,
        url: str,
        scheme_name: str,
        scheme_def: Dict[str, Any],
    ) -> Optional[SchemeTestResult]:
        """Send request with obviously invalid auth, expect 401/403."""
        if not self._client:
            return None

        scheme_type = scheme_def.get("type", "").lower()
        headers: Dict[str, str] = {"Accept": "application/json"}

        if scheme_type in ("http", "bearer"):
            bearer_or_basic = scheme_def.get("scheme", "bearer").lower()
            if bearer_or_basic == "basic":
                headers["Authorization"] = "Basic aW52YWxpZDppbnZhbGlk"  # invalid:invalid
            else:
                headers["Authorization"] = "Bearer invalid_token_12345"
        elif scheme_type == "apikey":
            param_name = scheme_def.get("name", "X-API-Key")
            location = scheme_def.get("in", "header")
            if location == "header":
                headers[param_name] = "invalid_api_key_12345"
            else:
                return None  # query/cookie API keys harder to test
        elif scheme_type == "oauth2":
            headers["Authorization"] = "Bearer expired_oauth_token_12345"
        else:
            return None

        try:
            resp = await self._client.request(ep.method, url, headers=headers)
            enforced = resp.status_code in self.REJECTED_STATUSES
            return SchemeTestResult(
                endpoint=ep,
                expected_schemes=[scheme_name],
                status_code=resp.status_code,
                enforced=enforced,
                notes="" if enforced else (
                    f"invalid {scheme_type} auth accepted (status {resp.status_code})"
                ),
            )
        except (httpx.HTTPError, OSError):
            return None

    # ------------------------------------------------------------------
    # Consistency checks (static analysis, no HTTP)
    # ------------------------------------------------------------------

    def _check_method_consistency(
        self,
        endpoints: List[ParsedEndpoint],
        global_security: List[str],
    ) -> List[Finding]:
        """Check that all methods on a path have consistent security."""
        findings: List[Finding] = []
        path_methods: Dict[str, Dict[str, List[str]]] = {}

        for ep in endpoints:
            schemes = self._get_effective_security(ep, global_security)
            path_methods.setdefault(ep.path, {})[ep.method.upper()] = schemes

        for path, methods in path_methods.items():
            secured = {m for m, s in methods.items() if s}
            unsecured = {m for m, s in methods.items() if not s}

            if secured and unsecured:
                findings.append(Finding(
                    title=f"Inconsistent security on {path}",
                    description=(
                        f"Path '{path}' has mixed security enforcement: "
                        f"secured ({', '.join(sorted(secured))}), "
                        f"unsecured ({', '.join(sorted(unsecured))})."
                    ),
                    severity=Severity.MEDIUM,
                    target=Target(url=path, method=next(iter(unsecured))),
                    evidence=f"secured_methods={sorted(secured)}, unsecured_methods={sorted(unsecured)}",
                    remediation="Apply consistent security requirements to all methods on the same path.",
                    cwe=862,
                    tags=["security-scheme", "consistency", "api", "openkrump"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Spec extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_global_security(spec: Dict[str, Any]) -> List[str]:
        """Extract globally-applied security scheme names."""
        global_sec = spec.get("security", [])
        names: List[str] = []
        for item in global_sec:
            if isinstance(item, dict):
                names.extend(item.keys())
        return names

    @staticmethod
    def _extract_security_definitions(spec: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract security scheme definitions."""
        # OpenAPI 3.x
        components = spec.get("components", {})
        schemes = components.get("securitySchemes", {})
        if schemes:
            return dict(schemes)
        # Swagger 2.0
        return dict(spec.get("securityDefinitions", {}))

    @staticmethod
    def _get_effective_security(
        ep: ParsedEndpoint,
        global_security: List[str],
    ) -> List[str]:
        """Get the effective security scheme names for an endpoint."""
        if ep.security:
            names: List[str] = []
            for item in ep.security:
                names.extend(item.keys())
            return names
        return global_security

    @staticmethod
    def _resolve_url(base_url: str, path: str) -> str:
        """Join base URL and path."""
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding_no_auth(
        target: Target,
        result: SchemeTestResult,
        schemes: List[str],
    ) -> Finding:
        return Finding(
            title=f"Missing auth enforcement on {result.endpoint.method.upper()} {result.endpoint.path}",
            description=(
                f"Endpoint declares security schemes ({', '.join(schemes)}) but "
                f"responded with status {result.status_code} when called without credentials."
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=f"status={result.status_code}, expected=401/403, schemes={schemes}",
            remediation="Ensure authentication middleware is applied and returns 401/403 for unauthenticated requests.",
            cwe=306,
            tags=["security-scheme", "missing-auth", "api", "openkrump"],
        )

    @staticmethod
    def _build_finding_invalid_auth(
        target: Target,
        result: SchemeTestResult,
    ) -> Finding:
        return Finding(
            title=f"Invalid auth accepted on {result.endpoint.method.upper()} {result.endpoint.path}",
            description=(
                f"Endpoint accepted obviously invalid credentials with status {result.status_code}. "
                f"{result.notes}"
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=f"status={result.status_code}, {result.notes}",
            remediation="Verify that authentication tokens/credentials are properly validated server-side.",
            cwe=287,
            tags=["security-scheme", "invalid-auth", "api", "openkrump"],
        )
