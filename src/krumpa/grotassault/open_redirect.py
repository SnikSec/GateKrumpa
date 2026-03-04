"""
GrotAssault — Open redirect detection.

Tests for open redirect vulnerabilities in URL parameters.
"""

from __future__ import annotations

import logging
from typing import Any, List

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.open_redirect")


_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnTo", "next", "next_url", "target",
    "destination", "dest", "rurl", "continue", "forward",
    "goto", "callback", "callback_url", "ref", "referer",
]

_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://evil.example.com%2F%2F",
    "https://evil.example.com@legitimate.com",
    "javascript:alert(1)",
    "//evil.example.com/%2F..",
    "https:evil.example.com",
    "\tjavascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


class OpenRedirectChecker(HttpClientMixin):
    """Test for open redirect vulnerabilities."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def check(self, target: Target) -> List[Finding]:
        """Test for open redirects on a target."""
        if not self._client:
            return []

        findings: List[Finding] = []
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)

        # Test existing redirect-like parameters
        test_params = []
        for name in params:
            if name.lower() in _REDIRECT_PARAMS:
                test_params.append(name)

        # Also probe common redirect parameters
        for name in _REDIRECT_PARAMS:
            if name not in params:
                test_params.append(name)

        for param_name in test_params:
            for payload in _REDIRECT_PAYLOADS:
                try:
                    url = self._inject_param(target.url, param_name, payload)
                    resp = await self._client.request(
                        method="GET",
                        url=url,
                        # Don't follow redirects — we want to see the redirect itself
                    )

                    if self._is_redirect(resp, payload):
                        findings.append(Finding(
                            title=f"Open redirect via '{param_name}' parameter",
                            description=(
                                f"Parameter '{param_name}' on {target.url} allows "
                                f"redirects to external domains. Payload: {payload}"
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"param={param_name}, payload={payload}, status={resp.status_code}",
                            remediation=(
                                "Validate redirect URLs against an allowlist of trusted domains. "
                                "Never redirect to user-supplied URLs without validation."
                            ),
                            cwe=601,
                            tags=["open-redirect", "phishing"],
                        ))
                        break  # one payload per param is enough

                except Exception:
                    pass

        return findings

    @staticmethod
    def _is_redirect(resp: Any, payload: str) -> bool:
        """Check if the response is a redirect to our payload domain."""
        if resp.status_code in (301, 302, 303, 307, 308):
            location = ""
            if hasattr(resp, 'headers'):
                location = resp.headers.get("location", resp.headers.get("Location", ""))
            if "evil.example.com" in location:
                return True
        # Check if payload appears in response body (meta refresh, JS redirect)
        text = resp.text if hasattr(resp, 'text') else ""
        if "evil.example.com" in text and resp.status_code < 400:
            return True
        return False

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))
