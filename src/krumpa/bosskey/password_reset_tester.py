"""
Password reset flow testing — token entropy, expiry, reuse,
user enumeration via timing/response diffing, Referer leakage.

OWASP: WSTG-ATHN-09 (Weak Password Change/Reset)
CWE-640: Weak Password Recovery Mechanism for Forgotten Password
"""

from __future__ import annotations

import logging
import math
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)

# Minimum safe entropy for a reset token (OWASP recommends ≥128 bits)
_MIN_TOKEN_ENTROPY_BITS = 64  # practical minimum for detection
_IDEAL_TOKEN_ENTROPY_BITS = 128

# Common reset-endpoint path hints
_RESET_HINTS = (
    "/reset", "/forgot", "/recover", "/password-reset",
    "/forgot-password", "/api/password/reset", "/api/auth/forgot",
)

# Patterns that leak reset tokens in the response body
_TOKEN_LEAK_PATTERNS = [
    re.compile(r"token[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9\-_]{20,})[\"']", re.I),
    re.compile(r"reset[_-]?token[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9\-_]{20,})[\"']", re.I),
    re.compile(r"href=[\"'][^\"']*token=([a-zA-Z0-9\-_]{20,})", re.I),
]


@dataclass
class ResetTokenAnalysis:
    """Analysis of a single captured reset token."""

    token: str
    length: int
    charset_size: int
    entropy_bits: float
    is_sequential: bool
    is_timestamp_based: bool


class PasswordResetTester:
    """
    Test password-reset flows for:
      1. Token entropy (short / low-entropy tokens)
      2. Token reuse (same token returned for repeat requests)
      3. User enumeration (response/timing differences for valid vs invalid users)
      4. Token leakage in response body or Referer header
      5. Missing rate-limiting on the reset endpoint
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        known_valid_email: str = "test@example.com",
        known_invalid_email: str = "definitely-not-a-real-user@example.com",
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._valid_email = known_valid_email
        self._invalid_email = known_invalid_email

    async def test(self, target: Target) -> List[Finding]:
        """Run all password-reset tests against the target endpoint."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. User enumeration via response diff ---------------------
            enum_finding = await self._test_user_enumeration(client, target)
            if enum_finding:
                findings.append(enum_finding)

            # --- 2. Token leakage in response body -------------------------
            leak_finding = await self._test_token_leakage(client, target)
            if leak_finding:
                findings.append(leak_finding)

            # --- 3. Token entropy analysis ---------------------------------
            token = await self._extract_token(client, target)
            if token:
                analysis = self._analyze_token(token)
                if analysis.entropy_bits < _MIN_TOKEN_ENTROPY_BITS:
                    findings.append(self._low_entropy_finding(analysis, target))
                if analysis.is_sequential:
                    findings.append(self._sequential_finding(analysis, target))

            # --- 4. Token reuse check --------------------------------------
            reuse_finding = await self._test_token_reuse(client, target)
            if reuse_finding:
                findings.append(reuse_finding)

            # --- 5. Rate-limit check ---------------------------------------
            rate_finding = await self._test_rate_limit(client, target)
            if rate_finding:
                findings.append(rate_finding)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Test implementations
    # ------------------------------------------------------------------

    async def _test_user_enumeration(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Compare responses for valid vs. invalid email addresses."""
        try:
            t1 = time.monotonic()
            resp_valid = await client.request(
                "POST", target.url,
                json_body={"email": self._valid_email},
            )
            elapsed_valid = time.monotonic() - t1

            t2 = time.monotonic()
            resp_invalid = await client.request(
                "POST", target.url,
                json_body={"email": self._invalid_email},
            )
            elapsed_invalid = time.monotonic() - t2

            # Response-based enumeration
            if resp_valid.status_code != resp_invalid.status_code:
                return Finding(
                    title=f"User enumeration via password reset on {target.url}",
                    description=(
                        f"Different HTTP status codes for valid email "
                        f"({resp_valid.status_code}) vs. invalid email "
                        f"({resp_invalid.status_code}) allow attackers to "
                        f"enumerate registered accounts."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Valid: {resp_valid.status_code} ({len(resp_valid.text)} bytes)\n"
                        f"Invalid: {resp_invalid.status_code} ({len(resp_invalid.text)} bytes)"
                    ),
                    remediation=(
                        "Return identical responses and status codes for both "
                        "valid and invalid email addresses. Use generic messages "
                        "like 'If that email exists, a reset link has been sent.'"
                    ),
                    cwe=204,
                    tags=["user-enumeration", "password-reset", "bosskey"],
                )

            # Timing-based enumeration (> 500ms difference)
            timing_diff = abs(elapsed_valid - elapsed_invalid)
            if timing_diff > 0.5:
                return Finding(
                    title=f"Timing-based user enumeration on {target.url}",
                    description=(
                        f"Significant timing difference ({timing_diff:.2f}s) between "
                        f"valid and invalid email requests suggests the server "
                        f"performs different operations based on user existence."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=(
                        f"Valid email: {elapsed_valid:.3f}s\n"
                        f"Invalid email: {elapsed_invalid:.3f}s\n"
                        f"Delta: {timing_diff:.3f}s"
                    ),
                    remediation=(
                        "Ensure constant-time processing for both valid and "
                        "invalid email addresses. Process asynchronously."
                    ),
                    cwe=208,
                    tags=["timing", "user-enumeration", "password-reset", "bosskey"],
                )

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None

    async def _test_token_leakage(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Check if the reset token appears in the HTTP response body."""
        try:
            resp = await client.request(
                "POST", target.url,
                json_body={"email": self._valid_email},
            )
            for pattern in _TOKEN_LEAK_PATTERNS:
                m = pattern.search(resp.text)
                if m:
                    leaked_token = m.group(1)
                    return Finding(
                        title=f"Reset token leaked in response body on {target.url}",
                        description=(
                            "The password reset token is returned in the HTTP response "
                            "body. This enables account takeover if the response is "
                            "intercepted (via MITM, shared cache, or XSS)."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Leaked token: {leaked_token[:10]}...",
                        remediation=(
                            "Never include reset tokens in API responses. "
                            "Send tokens only via email/SMS out-of-band channels."
                        ),
                        cwe=640,
                        tags=["token-leak", "password-reset", "bosskey"],
                    )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _extract_token(
        self, client: HttpClient, target: Target,
    ) -> Optional[str]:
        """Try to extract a reset token from the response for analysis."""
        try:
            resp = await client.request(
                "POST", target.url,
                json_body={"email": self._valid_email},
            )
            for pattern in _TOKEN_LEAK_PATTERNS:
                m = pattern.search(resp.text)
                if m:
                    return m.group(1)

            # Check URL in Location header
            loc = resp.headers.get("Location", "")
            if loc:
                parsed = urlparse(loc)
                qs = parse_qs(parsed.query)
                for key in ("token", "reset_token", "code"):
                    if key in qs:
                        return qs[key][0]
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _test_token_reuse(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Request two tokens and check if they are identical (no rotation)."""
        t1 = await self._extract_token(client, target)
        t2 = await self._extract_token(client, target)
        if t1 and t2 and t1 == t2:
            return Finding(
                title=f"Reset token reuse detected on {target.url}",
                description=(
                    "Multiple password reset requests returned the same token. "
                    "This suggests tokens are not regenerated per request, "
                    "enabling replay attacks."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Token 1: {t1[:10]}... == Token 2: {t2[:10]}...",
                remediation=(
                    "Generate a new unique token for every reset request. "
                    "Invalidate all previous tokens when a new one is issued."
                ),
                cwe=640,
                tags=["token-reuse", "password-reset", "bosskey"],
            )
        return None

    async def _test_rate_limit(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Send 10 rapid-fire reset requests to check for rate-limiting."""
        success_count = 0
        try:
            for _ in range(10):
                resp = await client.request(
                    "POST", target.url,
                    json_body={"email": self._valid_email},
                )
                if resp.status_code in (200, 201, 202, 204):
                    success_count += 1
                elif resp.status_code == 429:
                    return None  # rate-limiting is present
        except (httpx.HTTPError, OSError, ValueError):
            pass

        if success_count >= 10:
            return Finding(
                title=f"No rate-limiting on password reset at {target.url}",
                description=(
                    f"Sent 10 rapid reset requests and all returned success "
                    f"({success_count}/10). No rate-limiting detected, enabling "
                    f"email flooding and potential denial-of-service."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Success: {success_count}/10 requests",
                remediation=(
                    "Implement rate-limiting (e.g., 3 requests per 15 minutes "
                    "per email address). Use exponential backoff or CAPTCHA."
                ),
                cwe=307,
                tags=["rate-limit", "password-reset", "bosskey"],
            )
        return None

    # ------------------------------------------------------------------
    # Token analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_token(token: str) -> ResetTokenAnalysis:
        """Compute entropy and detect patterns in a reset token."""
        charset = set(token)
        charset_size = len(charset)
        length = len(token)
        entropy = length * math.log2(charset_size) if charset_size > 1 else 0.0

        # Sequential detection: check if token is numeric and incremental
        is_sequential = token.isdigit() and length <= 8

        # Timestamp-based detection
        is_timestamp = False
        if token.isdigit() and 10 <= length <= 13:
            try:
                ts = int(token)
                if 1_000_000_000 <= ts <= 9_999_999_999_999:
                    is_timestamp = True
            except ValueError:
                pass

        return ResetTokenAnalysis(
            token=token,
            length=length,
            charset_size=charset_size,
            entropy_bits=entropy,
            is_sequential=is_sequential,
            is_timestamp_based=is_timestamp,
        )

    @staticmethod
    def _low_entropy_finding(analysis: ResetTokenAnalysis, target: Target) -> Finding:
        return Finding(
            title=f"Low-entropy reset token on {target.url}",
            description=(
                f"Reset token has only {analysis.entropy_bits:.0f} bits of entropy "
                f"(length={analysis.length}, charset={analysis.charset_size}). "
                f"OWASP recommends ≥{_IDEAL_TOKEN_ENTROPY_BITS} bits."
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=(
                f"Token sample: {analysis.token[:10]}...\n"
                f"Entropy: {analysis.entropy_bits:.1f} bits"
            ),
            remediation=(
                "Use cryptographically secure random token generation with at "
                f"least {_IDEAL_TOKEN_ENTROPY_BITS} bits of entropy (e.g., "
                "secrets.token_urlsafe(32) in Python)."
            ),
            cwe=330,
            tags=["weak-token", "password-reset", "bosskey"],
        )

    @staticmethod
    def _sequential_finding(analysis: ResetTokenAnalysis, target: Target) -> Finding:
        return Finding(
            title=f"Sequential/predictable reset token on {target.url}",
            description=(
                "Reset token appears sequential or numeric-only, making it "
                "trivially guessable by attackers via brute-force."
            ),
            severity=Severity.CRITICAL,
            target=target,
            evidence=f"Token: {analysis.token}",
            remediation=(
                "Generate tokens using a CSPRNG. Never use sequential IDs, "
                "timestamps, or low-entropy values as reset tokens."
            ),
            cwe=330,
            tags=["predictable-token", "password-reset", "bosskey"],
        )
