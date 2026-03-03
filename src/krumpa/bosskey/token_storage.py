"""
Token storage analysis — detect insecure client-side token storage
(localStorage, sessionStorage, URL parameters, cookies without flags).

OWASP: WSTG-SESS-02, WSTG-ATHN-06
CWE-922: Insecure Storage of Sensitive Information
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)

# Patterns for detecting insecure token storage in JavaScript/HTML
_LOCALSTORAGE_PATTERNS = [
    re.compile(r"localStorage\.setItem\s*\(\s*['\"]([^'\"]*(?:token|jwt|auth|session|key|secret|credential)[^'\"]*)['\"]", re.I),
    re.compile(r"localStorage\[(['\"][^'\"]*(?:token|jwt|auth|session|key|secret)[^'\"]*['\"])\]", re.I),
    re.compile(r"localStorage\.([a-zA-Z_]*(?:token|jwt|auth|session)[a-zA-Z_]*)\s*=", re.I),
]

_SESSIONSTORAGE_PATTERNS = [
    re.compile(r"sessionStorage\.setItem\s*\(\s*['\"]([^'\"]*(?:token|jwt|auth|session|key|secret|credential)[^'\"]*)['\"]", re.I),
    re.compile(r"sessionStorage\[(['\"][^'\"]*(?:token|jwt|auth|session|key|secret)[^'\"]*['\"])\]", re.I),
]

_URL_TOKEN_PATTERNS = [
    re.compile(r"[?&](token|access_token|auth_token|jwt|session_id|api_key)=([^&\"'>\s]{10,})", re.I),
]

# Meta tag / window assignment patterns
_GLOBAL_LEAK_PATTERNS = [
    re.compile(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)', re.I),
    re.compile(r"window\.__TOKEN__\s*=\s*['\"]([^'\"]{10,})['\"]", re.I),
    re.compile(r"window\.token\s*=\s*['\"]([^'\"]{10,})['\"]", re.I),
]


class TokenStorageAnalyzer:
    """
    Inspect page content for insecure token storage practices:
      1. localStorage usage for auth tokens (XSS-accessible)
      2. sessionStorage usage for auth tokens (XSS-accessible)
      3. Tokens in URL parameters (Referer/log leakage)
      4. Tokens in global JS variables (XSS-accessible)
      5. Cookie flags audit (HttpOnly, Secure, SameSite)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all token-storage checks against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            resp = await client.request("GET", target.url)
            body = resp.text

            # --- 1. localStorage detection --------------------------------
            for pattern in _LOCALSTORAGE_PATTERNS:
                m = pattern.search(body)
                if m:
                    key_name = m.group(1)
                    findings.append(Finding(
                        title=f"Auth token stored in localStorage on {target.url}",
                        description=(
                            f"JavaScript stores a sensitive value with key '{key_name}' "
                            f"in localStorage. localStorage is accessible to any "
                            f"JavaScript running on the page, making it vulnerable "
                            f"to XSS-based token theft."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"localStorage key: {key_name}",
                        remediation=(
                            "Store authentication tokens in HttpOnly cookies instead "
                            "of localStorage. If localStorage is required, implement "
                            "strong XSS protections and use short-lived tokens."
                        ),
                        cwe=922,
                        tags=["token-storage", "localstorage", "xss-risk", "bosskey"],
                    ))
                    break  # one finding per storage type

            # --- 2. sessionStorage detection --------------------------------
            for pattern in _SESSIONSTORAGE_PATTERNS:
                m = pattern.search(body)
                if m:
                    key_name = m.group(1)
                    findings.append(Finding(
                        title=f"Auth token stored in sessionStorage on {target.url}",
                        description=(
                            f"JavaScript stores a sensitive value with key '{key_name}' "
                            f"in sessionStorage. While better than localStorage "
                            f"(tab-scoped), it is still accessible to XSS payloads."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"sessionStorage key: {key_name}",
                        remediation=(
                            "Prefer HttpOnly cookies for token storage. "
                            "If sessionStorage is needed, ensure robust XSS defenses."
                        ),
                        cwe=922,
                        tags=["token-storage", "sessionstorage", "bosskey"],
                    ))
                    break

            # --- 3. Tokens in URL parameters --------------------------------
            for pattern in _URL_TOKEN_PATTERNS:
                matches = pattern.findall(body)
                if matches:
                    param_name = matches[0][0] if isinstance(matches[0], tuple) else matches[0]
                    findings.append(Finding(
                        title=f"Token in URL parameter on {target.url}",
                        description=(
                            f"A token ('{param_name}') appears in a URL parameter. "
                            f"Tokens in URLs leak via Referer headers, browser "
                            f"history, server logs, and proxy logs."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"URL parameter: {param_name}",
                        remediation=(
                            "Transmit tokens via HTTP headers (Authorization) or "
                            "POST body parameters, never in URL query strings."
                        ),
                        cwe=598,
                        tags=["token-storage", "url-token", "bosskey"],
                    ))
                    break

            # --- 4. Global JS variable exposure ----------------------------
            for pattern in _GLOBAL_LEAK_PATTERNS:
                m = pattern.search(body)
                if m:
                    findings.append(Finding(
                        title=f"Token exposed in global scope on {target.url}",
                        description=(
                            "A token or secret is assigned to a global JavaScript "
                            "variable or embedded in a meta tag, making it accessible "
                            "to any script on the page (including injected XSS)."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"Matched: {m.group(0)[:80]}...",
                        remediation=(
                            "Avoid embedding tokens in HTML or global JS variables. "
                            "Use HttpOnly cookies or fetch tokens via authenticated API calls."
                        ),
                        cwe=922,
                        tags=["token-storage", "global-scope", "bosskey"],
                    ))
                    break

            # --- 5. Cookie flag audit (from Set-Cookie headers) -----------
            set_cookies = resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, "get_list") else []
            if not set_cookies:
                # Fallback for headers that don't support get_list
                sc = resp.headers.get("Set-Cookie", "")
                set_cookies = [sc] if sc else []

            for sc in set_cookies:
                sc_lower = sc.lower()
                cookie_name = sc.split("=", 1)[0].strip()

                if "httponly" not in sc_lower:
                    findings.append(Finding(
                        title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                        description=(
                            f"Cookie '{cookie_name}' is set without the HttpOnly flag. "
                            f"JavaScript (including XSS payloads) can access this cookie."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Set-Cookie: {sc[:100]}",
                        remediation="Add the HttpOnly flag to all session/auth cookies.",
                        cwe=1004,
                        tags=["cookie-flags", "token-storage", "bosskey"],
                    ))

                if target.url.startswith("https://") and "secure" not in sc_lower:
                    findings.append(Finding(
                        title=f"Cookie '{cookie_name}' missing Secure flag",
                        description=(
                            f"Cookie '{cookie_name}' on an HTTPS endpoint lacks the "
                            f"Secure flag. It may be sent over HTTP connections."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Set-Cookie: {sc[:100]}",
                        remediation="Add the Secure flag to all cookies on HTTPS sites.",
                        cwe=614,
                        tags=["cookie-flags", "token-storage", "bosskey"],
                    ))

        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.debug("Token storage analysis error on %s: %s", target.url, exc)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings
