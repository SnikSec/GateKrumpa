"""
Auth scheme enforcement — verify that protected endpoints return 401/403
when credentials are stripped or replaced with invalid values.

OWASP Testing Guide: OTG-AUTHN-001 / WSTG-ATHN-01
CWE-306: Missing Authentication for Critical Function
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)

# Status codes that indicate access was correctly denied
_DENIED_CODES = frozenset({401, 403, 407})

# Status codes that suggest an authentication bypass
_BYPASS_CODES = frozenset({200, 201, 202, 204, 301, 302, 307, 308})


@dataclass
class SchemeTestResult:
    """Outcome of a single scheme-enforcement probe."""

    url: str
    method: str
    test_name: str
    original_status: int
    stripped_status: int
    bypassed: bool
    evidence: str = ""


class AuthSchemeEnforcer:
    """
    Send requests *without* credentials (or with invalid ones) to endpoints
    that should require authentication, and verify that 401/403 is returned.

    Tests:
      1. Strip all auth headers / cookies entirely.
      2. Send an empty ``Authorization`` header.
      3. Send a malformed bearer token.
      4. Send an expired / obviously fake JWT.
      5. Strip only the session cookie (if present).
    """

    _FAKE_JWT = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFub24ifQ."
    )

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(
        self,
        target: Target,
        *,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Run all scheme-enforcement probes against *target*.

        *auth_headers* / *auth_cookies* override what is extracted from the
        target.  If blank, the method tries to infer from ``target.headers``
        and ``target.metadata``.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        # Collect the "good" auth material
        good_headers = dict(auth_headers or {})
        if not good_headers:
            for key in ("Authorization", "X-Api-Key", "Cookie"):
                val = target.headers.get(key, "")
                if val:
                    good_headers[key] = val

        good_cookies = dict(auth_cookies or {})
        if not good_cookies:
            good_cookies = target.metadata.get("cookies_dict", {})

        if not good_headers and not good_cookies:
            logger.debug("No auth material available for %s — skipping", target.url)
            return findings

        try:
            # --- Baseline (with auth) -----------------------------------------
            baseline_status = await self._send(
                client, target, extra_headers=good_headers,
            )

            # Only test if baseline succeeds (endpoint is actually protected)
            if baseline_status not in _BYPASS_CODES:
                logger.debug(
                    "Baseline already denied (%d) for %s — skipping", baseline_status, target.url,
                )
                return findings

            # --- Test 1: Strip ALL auth headers -------------------------------
            result = await self._probe(
                client, target, baseline_status,
                test_name="Strip all auth headers",
                extra_headers={},
            )
            if result and result.bypassed:
                findings.append(self._to_finding(result, target))

            # --- Test 2: Empty Authorization header ---------------------------
            result = await self._probe(
                client, target, baseline_status,
                test_name="Empty Authorization header",
                extra_headers={"Authorization": ""},
            )
            if result and result.bypassed:
                findings.append(self._to_finding(result, target))

            # --- Test 3: Malformed bearer token -------------------------------
            result = await self._probe(
                client, target, baseline_status,
                test_name="Malformed bearer token",
                extra_headers={"Authorization": "Bearer INVALID-TOKEN-12345"},
            )
            if result and result.bypassed:
                findings.append(self._to_finding(result, target))

            # --- Test 4: alg=none JWT ----------------------------------------
            result = await self._probe(
                client, target, baseline_status,
                test_name="alg=none JWT",
                extra_headers={"Authorization": f"Bearer {self._FAKE_JWT}"},
            )
            if result and result.bypassed:
                findings.append(self._to_finding(result, target))

            # --- Test 5: Strip session cookie only ----------------------------
            if good_cookies:
                stripped_headers = dict(good_headers)
                stripped_headers.pop("Cookie", None)
                result = await self._probe(
                    client, target, baseline_status,
                    test_name="Strip session cookie",
                    extra_headers=stripped_headers,
                )
                if result and result.bypassed:
                    findings.append(self._to_finding(result, target))

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _probe(
        self,
        client: HttpClient,
        target: Target,
        baseline_status: int,
        *,
        test_name: str,
        extra_headers: Dict[str, str],
    ) -> Optional[SchemeTestResult]:
        """Send a request with *extra_headers* instead of real auth."""
        try:
            status = await self._send(client, target, extra_headers=extra_headers)
        except (httpx.HTTPError, OSError, ValueError):
            return None

        bypassed = status in _BYPASS_CODES
        return SchemeTestResult(
            url=target.url,
            method=target.method,
            test_name=test_name,
            original_status=baseline_status,
            stripped_status=status,
            bypassed=bypassed,
            evidence=(
                f"Baseline {baseline_status} → {test_name} → {status}"
            ),
        )

    async def _send(
        self,
        client: HttpClient,
        target: Target,
        *,
        extra_headers: Dict[str, str],
    ) -> int:
        """Fire the request and return the status code."""
        resp = await client.request(
            target.method,
            target.url,
            headers=extra_headers or None,
        )
        return resp.status_code

    @staticmethod
    def _to_finding(result: SchemeTestResult, target: Target) -> Finding:
        return Finding(
            title=f"Missing authentication: {result.test_name} on {target.url}",
            description=(
                f"Endpoint {result.method} {result.url} returned HTTP "
                f"{result.stripped_status} when credentials were "
                f"{'stripped' if result.test_name.startswith('Strip') else 'replaced'} "
                f"({result.test_name}). Expected 401/403."
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=result.evidence,
            remediation=(
                "Enforce authentication on all protected endpoints. "
                "Validate credentials server-side and return 401/403 "
                "when authentication is missing or invalid."
            ),
            cwe=306,
            tags=["auth-bypass", "missing-auth", "bosskey"],
        )
