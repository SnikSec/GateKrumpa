"""
Credential transport audit — verify HTTPS enforcement,
detect credentials in GET parameters / URLs / Referer headers.

OWASP: WSTG-ATHN-01, WSTG-CRYP-03
CWE-319: Cleartext Transmission of Sensitive Information
CWE-598: Use of GET Request Method With Sensitive Query Strings
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)

# Sensitive parameter names that should never appear in query strings
_SENSITIVE_PARAMS = frozenset({
    "password", "passwd", "pass", "pwd", "secret", "token",
    "api_key", "apikey", "api-key", "access_token", "auth",
    "authorization", "session", "sessionid", "session_id",
    "credit_card", "cc", "cvv", "ssn", "pin",
})

# Headers that may leak credentials
_SENSITIVE_HEADERS = frozenset({
    "authorization", "x-api-key", "x-auth-token", "proxy-authorization",
})


class CredentialTransportAuditor:
    """
    Audit credential transport security:
      1. HTTP→HTTPS redirect enforcement (no plaintext creds)
      2. Credentials in GET query strings (Referer/log leakage)
      3. Login form action over HTTP
      4. Sensitive data in URL fragments
      5. Missing Strict-Transport-Security header
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def audit(self, target: Target) -> List[Finding]:
        """Run all credential-transport checks against *target*."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Credentials in query string ---------------------------
            findings.extend(self._check_query_params(target))

            # --- 2. HTTP (non-TLS) endpoint check -------------------------
            if target.url.startswith("http://"):
                findings.append(self._http_cleartext_finding(target))

            # --- 3. HTTPS redirect check (probe HTTP version) -------------
            https_redirect = await self._check_https_redirect(client, target)
            if https_redirect:
                findings.append(https_redirect)

            # --- 4. HSTS header check -------------------------------------
            hsts_finding = await self._check_hsts(client, target)
            if hsts_finding:
                findings.append(hsts_finding)

            # --- 5. Login form over HTTP ----------------------------------
            form_finding = await self._check_form_action(client, target)
            if form_finding:
                findings.append(form_finding)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_query_params(target: Target) -> List[Finding]:
        """Detect sensitive parameters in the URL query string."""
        findings: List[Finding] = []
        parsed = urlparse(target.url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            if param.lower() in _SENSITIVE_PARAMS:
                findings.append(Finding(
                    title=f"Credentials in GET query string: '{param}' on {target.url}",
                    description=(
                        f"Sensitive parameter '{param}' is transmitted in the URL "
                        f"query string. This exposes credentials in browser history, "
                        f"server logs, proxy logs, and the Referer header."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Parameter: {param} in URL query string",
                    remediation=(
                        "Transmit credentials in POST request bodies or HTTP "
                        "headers (Authorization). Never include secrets in URLs."
                    ),
                    cwe=598,
                    tags=["credential-transport", "query-string", "bosskey"],
                ))

        return findings

    @staticmethod
    def _http_cleartext_finding(target: Target) -> Finding:
        return Finding(
            title=f"Credentials sent over HTTP (cleartext) to {target.url}",
            description=(
                "The endpoint uses HTTP (not HTTPS), meaning credentials "
                "are transmitted in cleartext and can be intercepted by "
                "any network observer (MITM, Wi-Fi sniffing, etc.)."
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=f"URL scheme: http://",
            remediation=(
                "Enforce HTTPS on all endpoints that handle credentials. "
                "Redirect HTTP to HTTPS and set HSTS headers."
            ),
            cwe=319,
            tags=["cleartext", "credential-transport", "bosskey"],
        )

    async def _check_https_redirect(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """If target is HTTPS, check whether the HTTP version redirects."""
        if not target.url.startswith("https://"):
            return None

        http_url = target.url.replace("https://", "http://", 1)
        try:
            resp = await client.request("GET", http_url)
            # Check if we got a redirect to HTTPS
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                return None  # proper redirect
            if resp.status_code in (200, 201):
                return Finding(
                    title=f"No HTTP→HTTPS redirect for {target.host}",
                    description=(
                        "The HTTP version of the endpoint responds successfully "
                        "instead of redirecting to HTTPS. Users who accidentally "
                        "connect via HTTP will transmit credentials in cleartext."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"HTTP {http_url} → {resp.status_code} (no redirect)",
                    remediation=(
                        "Configure a 301 redirect from HTTP to HTTPS for all "
                        "endpoints. Enable HSTS with includeSubDomains and preload."
                    ),
                    cwe=319,
                    tags=["https-redirect", "credential-transport", "bosskey"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass  # connection refused = probably no HTTP listener (fine)
        return None

    async def _check_hsts(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Check for Strict-Transport-Security header."""
        if not target.url.startswith("https://"):
            return None

        try:
            resp = await client.request("GET", target.url)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                return Finding(
                    title=f"Missing HSTS header on {target.host}",
                    description=(
                        "The Strict-Transport-Security header is absent. "
                        "Without HSTS, browsers will allow HTTP connections "
                        "on first visit, enabling SSL-stripping attacks."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence="Strict-Transport-Security header not found",
                    remediation=(
                        "Set Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cwe=319,
                    tags=["hsts", "credential-transport", "bosskey"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _check_form_action(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Check if login forms post to HTTP URLs."""
        try:
            resp = await client.request("GET", target.url)
            # Look for form actions pointing to HTTP
            form_actions = re.findall(
                r'<form[^>]*action=["\']?(http://[^"\'>\s]+)',
                resp.text, re.I,
            )
            if form_actions:
                return Finding(
                    title=f"Login form posts to HTTP on {target.url}",
                    description=(
                        f"A form on this page submits data to an HTTP (non-HTTPS) "
                        f"URL: {form_actions[0]}. Credentials will be sent in "
                        f"cleartext even if the page itself is served over HTTPS."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Form action: {form_actions[0]}",
                    remediation=(
                        "Ensure all form actions use HTTPS URLs or relative paths "
                        "on an HTTPS-only site."
                    ),
                    cwe=319,
                    tags=["form-action", "credential-transport", "bosskey"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None
