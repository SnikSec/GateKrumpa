"""
BossKey — Account lockout tester.

Tests for:
- Account lockout after N failed attempts
- Lockout bypass via IP rotation headers
- Missing rate limiting on auth endpoints
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.bosskey.lockout_tester")


_ROTATION_HEADERS = [
    ("X-Forwarded-For", "127.0.0.{i}"),
    ("X-Real-IP", "10.0.0.{i}"),
    ("X-Originating-IP", "192.168.1.{i}"),
    ("X-Client-IP", "172.16.0.{i}"),
    ("True-Client-IP", "10.10.{i}.1"),
    ("CF-Connecting-IP", "1.2.{i}.4"),
]


@dataclass
class LockoutResult:
    """Result of lockout testing."""
    locked_out_after: int  # 0 if never locked out
    total_attempts: int
    rate_limited: bool
    bypass_possible: bool  # True if header rotation bypasses lockout
    bypass_header: str = ""


class AccountLockoutTester:
    """Test account lockout mechanisms and rate limiting."""

    def __init__(
        self,
        http_client: Any = None,
        *,
        max_attempts: int = 20,
    ) -> None:
        self._client = http_client
        self._owns_client = False
        self._max_attempts = max_attempts

    async def test(self, target: Target) -> List[Finding]:
        """Test lockout behaviour on an auth endpoint."""
        if not self._client:
            return []

        findings: List[Finding] = []

        # Phase 1: Test basic lockout
        result = await self._test_lockout(target)

        if result.locked_out_after == 0:
            findings.append(Finding(
                title="No account lockout detected",
                description=(
                    f"Endpoint {target.url} did not lock out after "
                    f"{result.total_attempts} failed login attempts. "
                    f"This enables credential brute-force attacks."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"attempts={result.total_attempts}, lockout=none",
                remediation="Implement progressive account lockout after 5-10 failed attempts. Use CAPTCHA and rate limiting.",
                cwe=307,
                tags=["lockout", "brute-force", "authentication"],
            ))

        if not result.rate_limited:
            findings.append(Finding(
                title="No rate limiting on authentication endpoint",
                description=(
                    f"Endpoint {target.url} does not appear to rate-limit "
                    f"authentication attempts. {result.total_attempts} requests "
                    f"were accepted without throttling."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"attempts={result.total_attempts}, rate_limited=false",
                remediation="Implement rate limiting on authentication endpoints. Use progressive delays.",
                cwe=799,
                tags=["rate-limit", "brute-force", "authentication"],
            ))

        # Phase 2: Test lockout bypass via header rotation
        if result.locked_out_after > 0:
            bypass_result = await self._test_bypass(target, result.locked_out_after)
            if bypass_result.bypass_possible:
                findings.append(Finding(
                    title=f"Account lockout bypass via {bypass_result.bypass_header}",
                    description=(
                        f"Account lockout on {target.url} can be bypassed by "
                        f"rotating the {bypass_result.bypass_header} header. "
                        f"The server uses client-provided IP headers for lockout tracking."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"bypass_header={bypass_result.bypass_header}",
                    remediation="Use the actual client IP for lockout, not X-Forwarded-For or similar headers.",
                    cwe=290,
                    tags=["lockout-bypass", "authentication", "header-injection"],
                ))

        return findings

    def analyze_lockout(self, target: Target) -> List[Dict[str, Any]]:
        """Static analysis: check if the target looks like a login endpoint worth testing."""
        url = target.url.lower()
        hints = ("/login", "/signin", "/auth", "/token", "/api/login", "/api/auth", "/oauth")
        recommendations: List[Dict[str, Any]] = []
        for hint in hints:
            if hint in url:
                recommendations.append({
                    "target": target.url,
                    "test": "lockout",
                    "reason": f"URL matches login pattern '{hint}'",
                })
                break
        return recommendations

    async def _test_lockout(self, target: Target) -> LockoutResult:
        """Send N failed login attempts and detect lockout/rate-limiting."""
        locked_after = 0
        rate_limited = False

        for i in range(1, self._max_attempts + 1):
            try:
                resp = await self._client.request(
                    method="POST",
                    url=target.url,
                    json={"username": "lockout_test_user", "password": f"wrong_{i}"},
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break
                if resp.status_code == 423 or resp.status_code == 403:
                    locked_after = i
                    break
            except Exception:
                break

        return LockoutResult(
            locked_out_after=locked_after,
            total_attempts=self._max_attempts if locked_after == 0 and not rate_limited else max(locked_after, 1),
            rate_limited=rate_limited,
            bypass_possible=False,
        )

    async def _test_bypass(self, target: Target, lockout_threshold: int) -> LockoutResult:
        """Test if lockout can be bypassed via IP header rotation."""
        for header_name, pattern in _ROTATION_HEADERS:
            # First, trigger lockout
            success_count = 0
            for i in range(lockout_threshold + 5):
                try:
                    headers = {header_name: pattern.format(i=i)}
                    resp = await self._client.request(
                        method="POST",
                        url=target.url,
                        json={"username": "lockout_test_user", "password": f"wrong_{i}"},
                        headers=headers,
                    )
                    if resp.status_code not in (423, 403, 429):
                        success_count += 1
                except Exception:
                    break

            if success_count > lockout_threshold:
                return LockoutResult(
                    locked_out_after=0,
                    total_attempts=success_count,
                    rate_limited=False,
                    bypass_possible=True,
                    bypass_header=header_name,
                )

        return LockoutResult(
            locked_out_after=lockout_threshold,
            total_attempts=lockout_threshold,
            rate_limited=False,
            bypass_possible=False,
        )
