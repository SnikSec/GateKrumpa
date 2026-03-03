"""
SneakyGits — HTTP method discovery.

Probes endpoints with OPTIONS and various HTTP verbs to detect:
  - Allowed methods (via the ``Allow`` header)
  - Verb tampering opportunities (methods that bypass security controls)
  - Unsafe methods exposed in production (PUT, DELETE, TRACE, etc.)

References:
  - OWASP Testing Guide: OTG-CONFIG-006
  - CWE-749: Exposed Dangerous Method or Function
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.sneakygits.method_discovery")

# HTTP methods that are potentially dangerous in production
_DANGEROUS_METHODS: Set[str] = {
    "PUT", "DELETE", "TRACE", "CONNECT", "PATCH",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
    "LOCK", "UNLOCK",
}

# Methods commonly used for verb tampering bypass
_TAMPER_METHODS: List[str] = [
    "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE",
    "PATCH", "PROPFIND", "INVENTED",
]


class MethodDiscovery:
    """Discover and assess allowed HTTP methods on target endpoints."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        check_verb_tampering: bool = True,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._check_verb_tampering = check_verb_tampering

    async def discover(self, target: Target) -> List[Finding]:
        """Run full method discovery on *target*."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=1)
        try:
            # 1. OPTIONS probe
            allowed = await self._options_probe(client, target)
            if allowed:
                findings.extend(self._assess_allowed(allowed, target))

            # 2. Verb tampering — try methods directly
            if self._check_verb_tampering:
                tamper_findings = await self._verb_tamper(client, target)
                findings.extend(tamper_findings)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # OPTIONS probe
    # ------------------------------------------------------------------

    async def _options_probe(
        self, client: HttpClient, target: Target,
    ) -> Set[str]:
        """Send OPTIONS and parse the Allow header."""
        try:
            resp = await client.request("OPTIONS", target.url)
            allow = resp.headers.get("allow", "")
            if allow:
                methods = {m.strip().upper() for m in allow.split(",")}
                logger.info("OPTIONS %s → Allow: %s", target.url, methods)
                return methods
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.debug("OPTIONS probe failed for %s: %s", target.url, exc)
        return set()

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _assess_allowed(
        allowed: Set[str], target: Target,
    ) -> List[Finding]:
        """Flag dangerous/unexpected methods advertised by the server."""
        findings: List[Finding] = []
        dangerous = allowed & _DANGEROUS_METHODS

        if "TRACE" in dangerous:
            findings.append(Finding(
                title=f"TRACE method enabled on {target.url}",
                description=(
                    "The TRACE method is enabled. It can be abused for "
                    "Cross-Site Tracing (XST) attacks to steal credentials "
                    "from HTTP headers."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Allow: {', '.join(sorted(allowed))}",
                remediation="Disable the TRACE method on the web server.",
                cwe=693,
                tags=["method-discovery", "trace", "xst"],
            ))
            dangerous.discard("TRACE")

        if dangerous:
            findings.append(Finding(
                title=f"Dangerous HTTP methods on {target.url}",
                description=(
                    f"The endpoint advertises potentially dangerous methods: "
                    f"{', '.join(sorted(dangerous))}. These may allow "
                    f"unauthorised data modification or information disclosure."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Allow: {', '.join(sorted(allowed))}",
                remediation=(
                    "Restrict HTTP methods to only those required. "
                    "Disable PUT, DELETE, TRACE, and WebDAV methods unless explicitly needed."
                ),
                cwe=749,
                tags=["method-discovery", "dangerous-methods"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Verb tampering
    # ------------------------------------------------------------------

    async def _verb_tamper(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Try unusual verbs to detect verb-tampering bypasses.

        If a restricted endpoint (returning 401/403 for GET) responds
        with 200 for a different method, that's a bypass.
        """
        findings: List[Finding] = []

        # Get baseline response code
        try:
            baseline = await client.request(target.method, target.url)
            base_status = baseline.status_code
        except (httpx.HTTPError, OSError, ValueError):
            return findings

        # Only worth testing if the endpoint is restricted
        if base_status not in (401, 403, 405):
            return findings

        bypassed: List[str] = []
        for method in _TAMPER_METHODS:
            if method == target.method:
                continue
            try:
                resp = await client.request(method, target.url)
                if resp.status_code == 200:
                    bypassed.append(method)
            except (httpx.HTTPError, OSError, ValueError):
                continue

        if bypassed:
            findings.append(Finding(
                title=f"HTTP verb tampering bypass on {target.url}",
                description=(
                    f"Endpoint returns {base_status} for {target.method} but "
                    f"responds 200 for: {', '.join(bypassed)}. "
                    f"This may allow authentication/authorization bypass."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Baseline: {target.method} → {base_status}; Bypass: {', '.join(bypassed)} → 200",
                remediation=(
                    "Enforce authorization checks regardless of HTTP method. "
                    "Reject or deny-list unexpected methods at the framework "
                    "or WAF level."
                ),
                cwe=287,
                tags=["method-discovery", "verb-tampering", "auth-bypass"],
            ))

        return findings
