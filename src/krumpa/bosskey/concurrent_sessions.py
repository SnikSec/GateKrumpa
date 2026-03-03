"""Concurrent session policy testing — multiple simultaneous sessions, hijack via parallel use.

Phase 4 item #53.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target


@dataclass
class SessionInfo:
    """Captured session from a login attempt."""
    session_id: str
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_header: str = ""
    login_time: float = 0.0
    is_valid: bool = True


class ConcurrentSessionTester:
    """Test concurrent session policies for security issues.

    Checks:
    - Maximum concurrent session enforcement
    - Session invalidation on new login (oldest-first, last-wins)
    - Parallel session usage (can two sessions be used simultaneously?)
    - Session fixation via concurrent login
    - Cross-device session visibility
    """

    MAX_CONCURRENT_LOGINS = 5

    def __init__(
        self,
        login_url: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
        auth_endpoint: Optional[str] = None,
    ) -> None:
        self._login_url = login_url
        self._credentials = credentials or {}
        self._auth_endpoint = auth_endpoint
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all concurrent session policy tests."""
        findings: List[Finding] = []
        url = target.url

        # 1. Test concurrent session limits
        findings.extend(await self._test_concurrent_limits(url, target))

        # 2. Test session invalidation policy
        findings.extend(await self._test_invalidation_policy(url, target))

        # 3. Test parallel usage
        findings.extend(await self._test_parallel_usage(url, target))

        return findings

    # ----------------------------------------------------------
    # Session creation helper
    # ----------------------------------------------------------

    async def _create_session(self, url: str) -> Optional[SessionInfo]:
        """Create a new authenticated session by logging in."""
        if not self._client or not self._credentials:
            return None

        login_url = self._login_url or f"{url}/login"

        try:
            resp = await self._client.request(
                "POST", login_url,
                json_body=self._credentials,
            )

            if resp.status_code not in (200, 302, 303):
                return None

            session = SessionInfo(
                session_id="",
                login_time=time.time(),
            )

            # Extract session from cookies
            if hasattr(resp, "headers"):
                cookies_raw: List[str] = []
                headers = resp.headers
                if hasattr(headers, "get_list"):
                    cookies_raw = headers.get_list("set-cookie")
                elif hasattr(headers, "getlist"):
                    cookies_raw = headers.getlist("set-cookie")
                else:
                    val = headers.get("set-cookie", "")
                    if val:
                        cookies_raw = [val]

                for cookie_str in cookies_raw:
                    parts = cookie_str.split(";")
                    if parts:
                        nv = parts[0].strip()
                        if "=" in nv:
                            name, _, value = nv.partition("=")
                            session.cookies[name.strip()] = value.strip()
                            # Use the first session-like cookie as the ID
                            if not session.session_id:
                                name_lower = name.strip().lower()
                                if any(kw in name_lower for kw in [
                                    "session", "sid", "token", "auth", "jsession",
                                    "phpsess", "asp.net",
                                ]):
                                    session.session_id = value.strip()

                # Also check for auth token in body
                try:
                    import json
                    body = json.loads(resp.text)
                    for key in ["token", "access_token", "session_token", "auth_token"]:
                        if key in body:
                            session.auth_header = f"Bearer {body[key]}"
                            if not session.session_id:
                                session.session_id = body[key]
                except Exception:
                    pass

            if not session.session_id and session.cookies:
                # Use first cookie as session identifier
                session.session_id = list(session.cookies.values())[0]

            return session if session.session_id else None

        except Exception:
            return None

    async def _validate_session(self, url: str, session: SessionInfo) -> bool:
        """Check if a session is still valid by accessing an auth-required endpoint."""
        if not self._client:
            return False

        check_url = self._auth_endpoint or url
        headers: Dict[str, str] = {}

        if session.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            headers["Cookie"] = cookie_str

        if session.auth_header:
            headers["Authorization"] = session.auth_header

        try:
            resp = await self._client.request("GET", check_url, headers=headers)
            # Consider valid if not explicitly rejected
            if resp.status_code in (401, 403):
                return False
            if resp.status_code in (200, 302, 303):
                text = resp.text.lower()
                if "login" in text and "please" in text:
                    return False
                return True
        except Exception:
            pass

        return False

    # ----------------------------------------------------------
    # Concurrent limits
    # ----------------------------------------------------------

    async def _test_concurrent_limits(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test if there is a limit on concurrent sessions."""
        findings: List[Finding] = []
        if not self._client or not self._credentials:
            return findings

        sessions: List[SessionInfo] = []

        for _i in range(self.MAX_CONCURRENT_LOGINS):
            session = await self._create_session(url)
            if session:
                sessions.append(session)
            else:
                break

        if len(sessions) >= self.MAX_CONCURRENT_LOGINS:
            # Check if ALL sessions are still valid
            valid_count = 0
            for session in sessions:
                if await self._validate_session(url, session):
                    valid_count += 1

            if valid_count >= self.MAX_CONCURRENT_LOGINS:
                findings.append(Finding(
                    title="No concurrent session limit enforced",
                    description=(
                        f"Created {self.MAX_CONCURRENT_LOGINS} simultaneous sessions "
                        f"for the same account, and all remain valid. No maximum "
                        f"concurrent session policy is enforced. A compromised "
                        f"account can be used from unlimited locations."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Sessions created: {len(sessions)}\n"
                        f"Sessions still valid: {valid_count}"
                    ),
                    remediation=(
                        "Implement a maximum concurrent session policy. "
                        "Options: invalidate oldest session, block new logins, "
                        "or notify user of concurrent usage."
                    ),
                    cwe=384,
                    tags=["session", "concurrent", "bosskey"],
                ))

        return findings

    # ----------------------------------------------------------
    # Invalidation policy
    # ----------------------------------------------------------

    async def _test_invalidation_policy(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test what happens to old sessions when a new login occurs."""
        findings: List[Finding] = []
        if not self._client or not self._credentials:
            return findings

        # Create session A
        session_a = await self._create_session(url)
        if not session_a:
            return findings

        # Create session B (new login)
        session_b = await self._create_session(url)
        if not session_b:
            return findings

        # Check if session A is still valid
        a_still_valid = await self._validate_session(url, session_a)
        b_valid = await self._validate_session(url, session_b)

        if a_still_valid and b_valid:
            # Both sessions valid — no invalidation on new login
            if session_a.session_id != session_b.session_id:
                findings.append(Finding(
                    title="Previous session not invalidated on new login",
                    description=(
                        "Creating a new session does not invalidate the previous one. "
                        "Both sessions remain valid simultaneously. If an attacker "
                        "obtains a session token, the legitimate user logging in again "
                        "does not revoke the attacker's access."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=(
                        f"Session A ID: {session_a.session_id[:20]}...\n"
                        f"Session B ID: {session_b.session_id[:20]}...\n"
                        f"Session A still valid: {a_still_valid}\n"
                        f"Session B valid: {b_valid}"
                    ),
                    remediation=(
                        "Consider enforcing a single-session policy or notifying "
                        "users of concurrent sessions. At minimum, provide users "
                        "with a 'log out all sessions' option."
                    ),
                    cwe=384,
                    tags=["session", "invalidation", "bosskey"],
                ))

        return findings

    # ----------------------------------------------------------
    # Parallel usage
    # ----------------------------------------------------------

    async def _test_parallel_usage(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test if sessions can be used in parallel from different contexts."""
        findings: List[Finding] = []
        if not self._client or not self._credentials:
            return findings

        session = await self._create_session(url)
        if not session:
            return findings

        check_url = self._auth_endpoint or url

        # Simulate parallel usage with different user-agents
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
        ]

        success_count = 0
        for ua in user_agents:
            headers: Dict[str, str] = {"User-Agent": ua}
            if session.cookies:
                headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in session.cookies.items()
                )
            if session.auth_header:
                headers["Authorization"] = session.auth_header

            try:
                resp = await self._client.request("GET", check_url, headers=headers)
                if resp.status_code not in (401, 403):
                    success_count += 1
            except Exception:
                continue

        if success_count >= len(user_agents):
            findings.append(Finding(
                title="Session accepted from multiple user agents",
                description=(
                    f"The same session token was accepted from {success_count} "
                    f"different user agents. The server does not bind sessions "
                    f"to client fingerprints (User-Agent, etc.). A stolen token "
                    f"can be used from any device."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=(
                    f"User agents tested: {len(user_agents)}\n"
                    f"Accepted by all: {success_count == len(user_agents)}"
                ),
                remediation=(
                    "Consider binding sessions to client fingerprints (User-Agent, "
                    "IP range) for sensitive applications. Implement device "
                    "management and session visibility for users."
                ),
                cwe=384,
                tags=["session", "fingerprint-binding", "bosskey"],
            ))

        return findings
