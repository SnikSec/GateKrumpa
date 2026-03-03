"""
BossKey — Session timeout / invalidation testing.

Tests idle timeout, absolute timeout, and logout invalidation to ensure
sessions are properly expired.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.bosskey.session_timeout")


@dataclass
class TimeoutTestResult:
    """Result of a timeout / invalidation test."""
    test_name: str
    endpoint: str
    is_vulnerable: bool = False
    detail: str = ""


class SessionTimeoutTester:
    """
    Test session timeout and invalidation behaviour.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        idle_timeout_seconds: float = 2.0,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._idle_timeout = idle_timeout_seconds

    async def test(self, target: Target, *, session_token: str = "") -> List[Finding]:
        """Run timeout and invalidation tests against *target*."""
        findings: List[Finding] = []

        # If a session token is provided, test it
        token = session_token or target.metadata.get("session_token", "")
        if token:
            findings.extend(await self._test_idle_timeout(target, token))
            findings.extend(await self._test_logout_invalidation(target, token))
        else:
            findings.extend(self._test_config_based(target))

        return findings

    def analyse_session_config(
        self,
        config: dict,
        target: Target,
    ) -> List[Finding]:
        """Check a session config dict for timeout weaknesses."""
        findings: List[Finding] = []

        idle_mins = config.get("idle_timeout_minutes", 0)
        if idle_mins == 0 or idle_mins > 30:
            findings.append(Finding(
                title="Session idle timeout too long or missing",
                description=f"Idle timeout is {idle_mins} minutes (recommended ≤ 15-30 min).",
                severity=Severity.MEDIUM,
                target=target,
                cwe=613,
                tags=["session", "timeout", "config"],
            ))

        absolute_mins = config.get("absolute_timeout_minutes", 0)
        if absolute_mins == 0 or absolute_mins > 480:
            findings.append(Finding(
                title="Session absolute timeout too long or missing",
                description=f"Absolute timeout is {absolute_mins} minutes (recommended ≤ 8 hours).",
                severity=Severity.LOW,
                target=target,
                cwe=613,
                tags=["session", "timeout", "config"],
            ))

        if not config.get("invalidate_on_password_change", False):
            findings.append(Finding(
                title="Sessions not invalidated on password change",
                description="Existing sessions survive password changes — compromised sessions remain active.",
                severity=Severity.MEDIUM,
                target=target,
                cwe=613,
                tags=["session", "invalidation", "config"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _test_idle_timeout(
        self, target: Target, token: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            # 1. Verify token works initially
            resp1 = await client.request(
                "GET", target.url,
                headers={"Authorization": f"Bearer {token}", **target.headers},
            )
            if getattr(resp1, "status_code", 0) not in (200, 201, 204):
                return findings  # token doesn't work, skip

            # 2. Wait for idle timeout period
            await asyncio.sleep(self._idle_timeout)

            # 3. Retry and check if still valid
            resp2 = await client.request(
                "GET", target.url,
                headers={"Authorization": f"Bearer {token}", **target.headers},
            )
            code2 = getattr(resp2, "status_code", 0)
            if code2 in (200, 201, 204):
                findings.append(Finding(
                    title="Session still valid after idle timeout",
                    description=(
                        f"Session token remained valid after {self._idle_timeout}s idle period "
                        f"on {target.url}."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Response status after idle: {code2}",
                    remediation="Implement server-side idle timeout (15-30 minutes recommended).",
                    cwe=613,
                    tags=["session", "timeout", "idle"],
                ))
        except Exception as exc:
            logger.debug("Idle timeout test error: %s", exc)
        finally:
            self._maybe_close(client)

        return findings

    async def _test_logout_invalidation(
        self, target: Target, token: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        logout_paths = ["/logout", "/api/logout", "/auth/logout", "/signout"]

        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(target.url)
            base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

            for path in logout_paths:
                logout_url = f"{base}{path}"
                try:
                    # Call logout
                    await client.request(
                        "POST", logout_url,
                        headers={"Authorization": f"Bearer {token}"},
                    )

                    # Try to use the token again
                    resp = await client.request(
                        "GET", target.url,
                        headers={"Authorization": f"Bearer {token}", **target.headers},
                    )
                    code = getattr(resp, "status_code", 0)
                    if code in (200, 201, 204):
                        findings.append(Finding(
                            title="Session not invalidated after logout",
                            description=(
                                f"Token remained valid after calling {logout_url}. "
                                f"Stolen tokens can be used indefinitely."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=f"Post-logout response: {code}",
                            remediation="Invalidate the session/token server-side on logout.",
                            cwe=613,
                            tags=["session", "logout", "invalidation"],
                        ))
                        break
                except Exception:
                    continue
        finally:
            self._maybe_close(client)

        return findings

    def _test_config_based(self, target: Target) -> List[Finding]:
        """Findings when no token is available for active testing."""
        return []

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
