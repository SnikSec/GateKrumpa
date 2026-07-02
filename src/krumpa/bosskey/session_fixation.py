"""
BossKey — Session fixation detection.

Checks whether the application rotates the session identifier after
authentication (pre-auth cookie vs. post-auth cookie).  If the session
ID remains unchanged, a session-fixation attack is possible (CWE-384).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.session_fixation")

# Common session cookie names
_SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
    "aspsessionid", "asp.net_sessionid", "connect.sid",
    "ci_session", "laravel_session", "rack.session",
    "token", "auth_token", "access_token",
}


@dataclass
class FixationTestResult(HttpClientMixin):
    """Result of a single session-fixation test."""
    endpoint: str
    pre_auth_cookies: Dict[str, str] = field(default_factory=dict)
    post_auth_cookies: Dict[str, str] = field(default_factory=dict)
    unchanged_ids: List[str] = field(default_factory=list)
    is_vulnerable: bool = False


class SessionFixationChecker(HttpClientMixin):
    """
    Detect session-fixation vulnerabilities by comparing session
    identifiers before and after authentication.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        session_cookie_names: Optional[List[str]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._cookie_names = set(
            n.lower() for n in (session_cookie_names or _SESSION_COOKIE_NAMES)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(
        self,
        target: Target,
        *,
        login_body: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """
        Perform the pre-auth → login → post-auth comparison.

        *target* should point to the login endpoint.  If *login_body* is
        ``None`` a dummy POST with ``{"username":"test","password":"test"}``
        is used (just to observe cookie rotation, not to succeed at login).
        """
        findings: List[Finding] = []
        result = await self._test(target, login_body=login_body)

        if result.is_vulnerable:
            names = ", ".join(result.unchanged_ids)
            findings.append(Finding(
                title="Session fixation — ID not rotated after login",
                description=(
                    f"Session cookie(s) [{names}] were not regenerated after "
                    f"submitting credentials to {result.endpoint}. An attacker "
                    f"who sets a known session ID before the victim logs in can "
                    f"hijack the authenticated session."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=(
                    f"Pre-auth: {result.pre_auth_cookies}\n"
                    f"Post-auth: {result.post_auth_cookies}\n"
                    f"Unchanged: {result.unchanged_ids}"
                ),
                remediation=(
                    "Regenerate the session identifier on every privilege-level "
                    "change (login, role switch, password change).  Invalidate "
                    "the old session server-side."
                ),
                cwe=384,
                tags=["session", "fixation", "auth"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Static / offline analysis (no HTTP required)
    # ------------------------------------------------------------------

    def analyse_cookie_rotation(
        self,
        pre_cookies: Dict[str, str],
        post_cookies: Dict[str, str],
        target: Target,
    ) -> List[Finding]:
        """
        Compare two cookie snapshots and report session-fixation risk.
        Useful when callers already have the cookies (e.g. from Crawler).
        """
        result = self._compare(pre_cookies, post_cookies, target.url)
        if not result.is_vulnerable:
            return []

        names = ", ".join(result.unchanged_ids)
        return [Finding(
            title="Session fixation — ID not rotated after login",
            description=(
                f"Session cookie(s) [{names}] unchanged between "
                f"pre-auth and post-auth snapshots for {target.url}."
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=(
                f"Pre-auth: {result.pre_auth_cookies}\n"
                f"Post-auth: {result.post_auth_cookies}\n"
                f"Unchanged: {result.unchanged_ids}"
            ),
            remediation="Regenerate session ID after authentication.",
            cwe=384,
            tags=["session", "fixation", "auth"],
        )]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _test(
        self,
        target: Target,
        *,
        login_body: Optional[Dict[str, str]] = None,
    ) -> FixationTestResult:
        """Run the full pre/post comparison via HTTP."""
        client = self._client
        if client is None:
            client = HttpClient(timeout=10.0, retries=0)

        try:
            # 1. GET the login page — capture pre-auth cookies
            pre_resp = await client.request("GET", target.url)
            pre_cookies = self._extract_session_cookies(
                dict(pre_resp.headers) if hasattr(pre_resp, "headers") else {}
            )

            # 2. POST credentials (or dummy body)
            body = login_body or {"username": "test", "password": "test"}
            post_resp = await client.request(
                "POST", target.url,
                json_body=body,
                headers={"Content-Type": "application/json"},
            )
            post_cookies = self._extract_session_cookies(
                dict(post_resp.headers) if hasattr(post_resp, "headers") else {}
            )

            return self._compare(pre_cookies, post_cookies, target.url)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    def _compare(
        self,
        pre: Dict[str, str],
        post: Dict[str, str],
        url: str,
    ) -> FixationTestResult:
        """Compare pre/post cookies and detect unchanged session IDs."""
        unchanged: List[str] = []
        for name, value in pre.items():
            if name in post and post[name] == value and value:
                unchanged.append(name)

        return FixationTestResult(
            endpoint=url,
            pre_auth_cookies=pre,
            post_auth_cookies=post,
            unchanged_ids=unchanged,
            is_vulnerable=len(unchanged) > 0,
        )

    def _extract_session_cookies(
        self, headers: Dict[str, str],
    ) -> Dict[str, str]:
        """Parse Set-Cookie headers and return session-related cookies."""
        cookies: Dict[str, str] = {}
        raw = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if not raw:
            return cookies

        # Handle multiple cookies (may be combined with comma or separate headers)
        for part in re.split(r",(?=[^;]*=)", raw):
            part = part.strip()
            m = re.match(r"([^=]+)=([^;]*)", part)
            if m:
                name = m.group(1).strip().lower()
                value = m.group(2).strip()
                if name in self._cookie_names:
                    cookies[name] = value

        return cookies
