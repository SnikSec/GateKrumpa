"""
SneakyGits — CORS Misconfiguration Tester.

Sends crafted ``Origin`` headers and inspects the
``Access-Control-Allow-*`` response headers to detect:

- Wildcard CORS (``*``) with credentials
- Origin reflection (mirror back any supplied origin)
- Null origin bypass
- Subdomain/prefix trust issues
"""

from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.sneakygits.cors")


class CorsChecker:
    """
    Test a target for CORS misconfiguration.

    Usage::

        checker = CorsChecker()
        findings = await checker.check(target)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """Run all CORS checks against a single target URL."""
        client = self._client or HttpClient()
        findings: List[Finding] = []

        try:
            parsed = urlparse(target.url)
            origin = f"{parsed.scheme}://{parsed.hostname}"

            # 1. Check if wildcard CORS with credentials is allowed
            findings.extend(await self._check_wildcard(client, target))

            # 2. Check if arbitrary origin is reflected
            findings.extend(await self._check_reflection(client, target, origin))

            # 3. Check null origin bypass
            findings.extend(await self._check_null_origin(client, target))

            # 4. Check prefix-match / substring bypass
            findings.extend(await self._check_prefix_bypass(client, target, origin))

        except (httpx.HTTPError, OSError) as exc:
            logger.warning("CORS check failed for %s: %s", target.url, exc)
        finally:
            if self._owns_client and not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    async def _check_wildcard(
        self, client: HttpClient, target: Target
    ) -> List[Finding]:
        """Detect wildcard CORS combined with Allow-Credentials."""
        resp = await client.get(
            target.url, headers={"Origin": "https://evil.example.com"}
        )
        acao = _get_header(resp, "Access-Control-Allow-Origin")
        acac = _get_header(resp, "Access-Control-Allow-Credentials")

        findings: List[Finding] = []

        if acao == "*" and acac and acac.lower() == "true":
            findings.append(Finding(
                title="CORS wildcard with credentials",
                description=(
                    "The server sets Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true.  This is technically "
                    "invalid per the spec, but some browsers/proxies may honor it, "
                    "allowing any site to make credentialed cross-origin requests."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac}"
                ),
                remediation=(
                    "Never combine CORS wildcard (*) with credentials.  "
                    "Validate the Origin against an allow-list."
                ),
                cwe=942,
                tags=["recon", "cors", "config"],
            ))

        return findings

    async def _check_reflection(
        self, client: HttpClient, target: Target, real_origin: str
    ) -> List[Finding]:
        """Detect if the server reflects any Origin it receives."""
        evil = "https://attacker.example.com"
        resp = await client.get(target.url, headers={"Origin": evil})
        acao = _get_header(resp, "Access-Control-Allow-Origin")
        acac = _get_header(resp, "Access-Control-Allow-Credentials")

        findings: List[Finding] = []

        if acao and acao == evil:
            severity = Severity.HIGH if (acac and acac.lower() == "true") else Severity.MEDIUM
            desc = (
                "The server reflects the supplied Origin header in "
                "Access-Control-Allow-Origin, allowing any website to read "
                "cross-origin responses."
            )
            if acac and acac.lower() == "true":
                desc += (
                    " Combined with Access-Control-Allow-Credentials: true, "
                    "this allows full credential theft (cookies, auth headers)."
                )
            findings.append(Finding(
                title="CORS origin reflection",
                description=desc,
                severity=severity,
                target=target,
                evidence=(
                    f"Request Origin: {evil}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                ),
                remediation=(
                    "Validate the Origin header against a strict allow-list.  "
                    "Do not reflect arbitrary origins."
                ),
                cwe=942,
                tags=["recon", "cors", "config"],
            ))

        return findings

    async def _check_null_origin(
        self, client: HttpClient, target: Target
    ) -> List[Finding]:
        """Detect if Origin: null is allowed (sandboxed iframe bypass)."""
        resp = await client.get(target.url, headers={"Origin": "null"})
        acao = _get_header(resp, "Access-Control-Allow-Origin")
        acac = _get_header(resp, "Access-Control-Allow-Credentials")

        findings: List[Finding] = []

        if acao and acao.lower() == "null":
            severity = Severity.MEDIUM if not (acac and acac.lower() == "true") else Severity.HIGH
            findings.append(Finding(
                title="CORS null origin allowed",
                description=(
                    "The server allows Origin: null.  Sandboxed iframes and "
                    "data: URIs send a null origin, enabling an attacker to "
                    "craft a page that makes credentialed cross-origin requests."
                ),
                severity=severity,
                target=target,
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                ),
                remediation="Reject Origin: null in your CORS configuration.",
                cwe=942,
                tags=["recon", "cors", "config"],
            ))

        return findings

    async def _check_prefix_bypass(
        self, client: HttpClient, target: Target, real_origin: str
    ) -> List[Finding]:
        """
        Detect prefix-based trust.

        If the real origin is ``https://example.com``, test whether
        ``https://example.com.evil.com`` is also trusted — indicating a
        regex or starts-with check instead of exact matching.
        """
        parsed = urlparse(real_origin)
        evil = f"{parsed.scheme}://{parsed.hostname}.evil.com"
        resp = await client.get(target.url, headers={"Origin": evil})
        acao = _get_header(resp, "Access-Control-Allow-Origin")

        findings: List[Finding] = []

        if acao and acao == evil:
            findings.append(Finding(
                title="CORS prefix/substring trust bypass",
                description=(
                    f"The server trusts '{evil}' as a valid origin, suggesting "
                    f"it uses prefix matching rather than exact origin validation. "
                    f"An attacker can register a domain like '{parsed.hostname}.evil.com' "
                    f"to bypass the CORS policy."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation=(
                    "Use exact string matching (or a proper URL-based allow-list) "
                    "for CORS origin validation."
                ),
                cwe=942,
                tags=["recon", "cors", "config"],
            ))

        return findings


def _get_header(resp, name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    if hasattr(resp.headers, "get"):
        return resp.headers.get(name)
    return None
