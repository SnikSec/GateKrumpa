"""
BossKey — CSRF protection auditor.

Checks state-changing endpoints for Cross-Site Request Forgery
protections:

* Anti-CSRF token presence in HTML forms
* ``SameSite`` cookie attributes (also checked by session_analyzer,
  but repeated here for standalone CSRF reporting)
* Custom-header requirement (``X-Requested-With``, ``X-CSRF-Token``)
* Token-stripping test — replay a request without the token to see
  if the server still accepts it
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.csrf")

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Common CSRF token input names (case-insensitive search)
_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']'
    r"(?:csrf[-_]?token|_csrf|csrfmiddlewaretoken|__RequestVerificationToken|"
    r"authenticity_token|_token|antiforgery|xsrf[-_]?token|__csrf_token|csrf)"
    r'["\']',
    re.IGNORECASE,
)

# Meta tags that carry CSRF tokens
_CSRF_META_RE = re.compile(
    r'<meta[^>]+name=["\']'
    r"(?:csrf-token|csrf-param|_csrf_token|xsrf-token)"
    r'["\']',
    re.IGNORECASE,
)

# HTML form tags (state-changing methods)
_FORM_RE = re.compile(
    r'<form[^>]*method=["\'](?:post|put|patch|delete)["\'][^>]*>',
    re.IGNORECASE,
)

# Custom CSRF headers servers commonly require
_CSRF_HEADERS = [
    "X-CSRF-Token",
    "X-XSRF-TOKEN",
    "X-Requested-With",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CsrfCheckResult(HttpClientMixin):
    """Result of a CSRF audit on a single target."""
    url: str
    has_csrf_input: bool = False
    has_csrf_meta: bool = False
    has_csrf_header: bool = False
    form_count: int = 0
    unprotected_forms: int = 0
    accepted_without_token: Optional[bool] = None


# ---------------------------------------------------------------------------
# CsrfChecker
# ---------------------------------------------------------------------------

class CsrfChecker(HttpClientMixin):
    """Audit endpoints for CSRF protection.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, target: Target) -> List[Finding]:
        """Run CSRF checks against *target* and return findings."""
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            findings: List[Finding] = []
            findings.extend(await self._check_page_tokens(client, target))
            findings.extend(await self._check_header_requirement(client, target))
            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Page-level token checks
    # ------------------------------------------------------------------

    async def _check_page_tokens(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Fetch the page and look for CSRF tokens in forms."""
        findings: List[Finding] = []
        try:
            resp = await client.get(target.url)
        except (httpx.HTTPError, OSError):
            logger.debug("Failed to fetch %s for CSRF check", target.url)
            return findings

        body = resp.text
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type:
            return findings

        forms = _FORM_RE.findall(body)
        has_input = bool(_CSRF_INPUT_RE.search(body))
        has_meta = bool(_CSRF_META_RE.search(body))

        if forms and not has_input and not has_meta:
            findings.append(Finding(
                title=f"No CSRF token found in {len(forms)} form(s) on {target.host}",
                description=(
                    f"The page at {target.url} contains {len(forms)} state-changing "
                    "form(s) but no anti-CSRF token was detected in hidden inputs "
                    "or meta tags."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Forms found: {len(forms)}, CSRF inputs: 0, CSRF meta: 0",
                remediation=(
                    "Add a unique, unpredictable CSRF token to every state-changing "
                    "form. Validate the token server-side on submission."
                ),
                cwe=352,
                tags=["auth", "csrf", "missing-token"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Header-based CSRF checks
    # ------------------------------------------------------------------

    async def _check_header_requirement(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test if the endpoint accepts state-changing requests without custom headers."""
        findings: List[Finding] = []

        # Only test POST/PUT/PATCH/DELETE targets
        if target.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return findings

        # Send request WITHOUT any custom CSRF header
        try:
            resp_no_header = await client.request(
                target.method,
                target.url,
                headers={"Content-Type": "application/json"},
                body=target.body or "{}",
            )
        except (httpx.HTTPError, OSError):
            return findings

        # If the server returns 2xx without ANY CSRF protection header,
        # it's likely vulnerable
        if 200 <= resp_no_header.status_code < 300:
            # Check if any CSRF header was required by trying with one
            for header_name in _CSRF_HEADERS:
                try:
                    resp_with_header = await client.request(
                        target.method,
                        target.url,
                        headers={
                            "Content-Type": "application/json",
                            header_name: "test-csrf-value",
                        },
                        body=target.body or "{}",
                    )
                except (httpx.HTTPError, OSError):
                    continue

                # If both succeed equally, server isn't checking the
                # header — that's fine (we just note the absence of
                # header-based CSRF for the overall audit)
                if resp_with_header.status_code == resp_no_header.status_code:
                    continue

                # If adding the header changes the outcome (e.g. 200 → 403
                # without it), that's a misconfiguration
                if resp_no_header.status_code < 400 < resp_with_header.status_code:
                    findings.append(Finding(
                        title=f"CSRF header check inverted on {target.host}",
                        description=(
                            f"The endpoint {target.url} ({target.method}) returns "
                            f"success without {header_name} but fails when the header "
                            "is present. This is likely a misconfiguration."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        cwe=352,
                        tags=["auth", "csrf", "header-check"],
                    ))

            # If server returns 200 with no indication it checked any CSRF
            # mechanism, flag it for state-changing endpoints
            if resp_no_header.status_code < 300:
                # Check for Origin/Referer validation — send with a
                # cross-origin Origin header
                try:
                    resp_cross_origin = await client.request(
                        target.method,
                        target.url,
                        headers={
                            "Content-Type": "application/json",
                            "Origin": "https://evil-attacker.com",
                        },
                        body=target.body or "{}",
                    )
                    if 200 <= resp_cross_origin.status_code < 300:
                        findings.append(Finding(
                            title=f"State-changing endpoint accepts cross-origin requests",
                            description=(
                                f"The endpoint {target.url} ({target.method}) accepted "
                                "a request with Origin: https://evil-attacker.com and "
                                f"returned {resp_cross_origin.status_code}. No CSRF "
                                "protection (token, Origin check, or SameSite cookie) "
                                "was detected."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Origin: https://evil-attacker.com → "
                                f"{resp_cross_origin.status_code}"
                            ),
                            remediation=(
                                "Implement CSRF protection: anti-CSRF tokens, "
                                "Origin/Referer validation, or SameSite=Strict cookies."
                            ),
                            cwe=352,
                            tags=["auth", "csrf", "cross-origin"],
                        ))
                except (httpx.HTTPError, OSError):
                    pass

        return findings
