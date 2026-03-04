"""
Multi-Factor Authentication (MFA) testing — bypass, brute-force,
backup codes, downgrade, step-skipping.

OWASP: WSTG-ATHN-11 (Testing Multi-Factor Authentication)
CWE-308: Use of Single-factor Authentication
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger(__name__)

# Common TOTP code space for brute-force attempts
_TOTP_CODES_SAMPLE = [
    "000000", "111111", "123456", "654321",
    "999999", "000001", "100000",
]

# Common backup code patterns
_BACKUP_CODE_PATTERNS = [
    re.compile(r"\b[A-Z0-9]{8}\b"),               # 8-char alphanumeric
    re.compile(r"\b\d{6}[- ]?\d{6}\b"),            # 6-6 digit pair
    re.compile(r"\b[a-f0-9]{8}[- ]?[a-f0-9]{8}\b"),  # hex pair
]

# MFA-related URL hints
_MFA_URL_HINTS = re.compile(
    r"(mfa|2fa|two.?factor|otp|totp|verify|challenge|second.?step)",
    re.IGNORECASE,
)


class MfaTester(HttpClientMixin):
    """
    Test MFA implementations for:
      1. Step-skip bypass (go directly to post-auth resource)
      2. TOTP brute-force (no lockout after multiple wrong codes)
      3. Backup code enumeration / reuse
      4. MFA downgrade (force weaker factor)
      5. Missing MFA on sensitive operations (profile change, password change)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def test(
        self,
        target: Target,
        mfa_endpoint: Optional[str] = None,
        post_auth_url: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Run all MFA tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Step-skip bypass ---
            f = await self._test_step_skip(
                client, target,
                mfa_endpoint=mfa_endpoint,
                post_auth_url=post_auth_url,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            if f:
                findings.append(f)

            # --- 2. TOTP brute-force resilience ---
            f = await self._test_totp_brute_force(
                client, target,
                mfa_endpoint=mfa_endpoint,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            if f:
                findings.append(f)

            # --- 3. Backup code issues ---
            backup_findings = await self._test_backup_codes(
                client, target,
                mfa_endpoint=mfa_endpoint,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            findings.extend(backup_findings)

            # --- 4. MFA downgrade ---
            f = await self._test_mfa_downgrade(
                client, target,
                mfa_endpoint=mfa_endpoint,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            if f:
                findings.append(f)

            # --- 5. Missing MFA on sensitive ops ---
            sensitive_findings = await self._test_missing_mfa_on_sensitive_ops(
                client, target,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            findings.extend(sensitive_findings)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_step_skip(
        self,
        client: HttpClient,
        target: Target,
        *,
        mfa_endpoint: Optional[str] = None,
        post_auth_url: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[Finding]:
        """
        After first-factor auth, skip the MFA step and try accessing
        a post-auth page directly.
        """
        if not post_auth_url:
            return None

        try:
            headers = dict(auth_headers or {})
            if auth_cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

            resp = await client.request(
                "GET", post_auth_url,
                headers=headers,
            )

            # If we get 200 without completing MFA, it's a bypass
            if resp.status_code in (200, 201):
                # Heuristic: check if the response looks like an authenticated page
                text = resp.text.lower()
                auth_indicators = ["dashboard", "profile", "welcome", "account", "logout"]
                if any(ind in text for ind in auth_indicators):
                    return Finding(
                        title=f"MFA step-skip bypass on {target.url}",
                        description=(
                            "After first-factor authentication, the MFA step can be skipped "
                            "by directly navigating to the post-authentication URL. "
                            "The server does not verify MFA completion before granting access."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=(
                            f"Post-auth URL: {post_auth_url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Auth indicators found in response"
                        ),
                        remediation=(
                            "Server-side session must track MFA completion state. "
                            "Enforce MFA verification on every request to protected resources. "
                            "Use middleware to check MFA status before granting access."
                        ),
                        cwe=308,
                        tags=["mfa-bypass", "step-skip", "bosskey"],
                    )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _test_totp_brute_force(
        self,
        client: HttpClient,
        target: Target,
        *,
        mfa_endpoint: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[Finding]:
        """Send multiple wrong TOTP codes and check for lockout/rate-limit."""
        endpoint = mfa_endpoint or target.url
        headers = dict(auth_headers or {})
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        accepted_count = 0
        lockout_triggered = False

        try:
            for code in _TOTP_CODES_SAMPLE:
                body = {"code": code, "otp": code, "totp": code}
                resp = await client.request(
                    "POST", endpoint,
                    json_body=body,
                    headers=headers,
                )

                if resp.status_code == 429:
                    lockout_triggered = True
                    break
                if resp.status_code in (200, 201):
                    accepted_count += 1

        except (httpx.HTTPError, OSError, ValueError):
            pass

        if not lockout_triggered and accepted_count == 0:
            # All rejected but no lockout either — check if we tried enough
            if len(_TOTP_CODES_SAMPLE) >= 5:
                return Finding(
                    title=f"No MFA brute-force protection on {target.url}",
                    description=(
                        f"Sent {len(_TOTP_CODES_SAMPLE)} incorrect TOTP codes "
                        f"without triggering account lockout or rate-limiting. "
                        f"An attacker could brute-force the 6-digit TOTP space "
                        f"(1,000,000 combinations) if not throttled."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=(
                        f"Codes tried: {len(_TOTP_CODES_SAMPLE)}\n"
                        f"Lockout: No\n"
                        f"Rate-limit: No"
                    ),
                    remediation=(
                        "Implement progressive lockout after 3-5 failed MFA attempts. "
                        "Use exponential backoff or temporary account freeze. "
                        "Send alerts to users on repeated MFA failures."
                    ),
                    cwe=307,
                    tags=["mfa", "brute-force", "rate-limit", "bosskey"],
                )
        return None

    async def _test_backup_codes(
        self,
        client: HttpClient,
        target: Target,
        *,
        mfa_endpoint: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Check for backup code exposure and reuse."""
        findings: List[Finding] = []
        _endpoint = mfa_endpoint or target.url

        try:
            # Try requesting backup codes endpoint
            for path_suffix in ["/backup-codes", "/recovery-codes", "/mfa/backup"]:
                url = target.url.rstrip("/") + path_suffix
                headers = dict(auth_headers or {})
                if auth_cookies:
                    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())
                resp = await client.request(
                    "GET", url,
                    headers=headers,
                )

                if resp.status_code in (200, 201):
                    # Check if backup codes are exposed in response
                    for pattern in _BACKUP_CODE_PATTERNS:
                        matches = pattern.findall(resp.text)
                        if len(matches) >= 3:
                            findings.append(Finding(
                                title=f"Backup codes exposed at {url}",
                                description=(
                                    f"Backup/recovery codes are accessible via GET request. "
                                    f"Found {len(matches)} potential code patterns. "
                                    f"Codes should only be shown once during MFA setup."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"URL: {url}\n"
                                    f"Codes found: {len(matches)} patterns"
                                ),
                                remediation=(
                                    "Backup codes should only be displayed once during MFA enrollment. "
                                    "Subsequent requests should show masked codes. "
                                    "Require re-authentication to view/regenerate codes."
                                ),
                                cwe=200,
                                tags=["mfa", "backup-codes", "information-disclosure", "bosskey"],
                            ))
                            break
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return findings

    async def _test_mfa_downgrade(
        self,
        client: HttpClient,
        target: Target,
        *,
        mfa_endpoint: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[Finding]:
        """Try forcing a weaker MFA method (SMS instead of TOTP)."""
        endpoint = mfa_endpoint or target.url
        headers = dict(auth_headers or {})
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        try:
            downgrade_payloads = [
                {"method": "sms", "type": "sms"},
                {"method": "email", "type": "email"},
                {"mfa_type": "sms"},
                {"mfa_type": "email"},
                {"factor": "sms"},
                {"preferred_method": "sms"},
            ]

            for payload in downgrade_payloads:
                resp = await client.request(
                    "POST", endpoint,
                    json_body=payload,
                    headers=headers,
                )

                if resp.status_code in (200, 201, 202):
                    text = resp.text.lower()
                    if any(kw in text for kw in ["sms", "sent", "code", "message"]):
                        return Finding(
                            title=f"MFA downgrade to weaker factor on {target.url}",
                            description=(
                                "The MFA endpoint accepts requests to change the "
                                "authentication factor to a weaker method (e.g., SMS). "
                                "This allows an attacker to downgrade from TOTP/hardware "
                                "token to SMS, which is vulnerable to SIM-swapping."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                            remediation=(
                                "Do not allow MFA method changes without full re-authentication. "
                                "Require the current MFA code before switching methods. "
                                "Consider disabling SMS-based MFA entirely."
                            ),
                            cwe=308,
                            tags=["mfa", "downgrade", "bosskey"],
                        )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _test_missing_mfa_on_sensitive_ops(
        self,
        client: HttpClient,
        target: Target,
        *,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Check if sensitive operations require MFA re-verification."""
        findings: List[Finding] = []
        headers = dict(auth_headers or {})
        if auth_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())

        sensitive_ops = [
            ("/password/change", "POST", {"old_password": "test", "new_password": "test2"}),
            ("/email/change", "POST", {"email": "new@example.com"}),
            ("/settings/security", "GET", None),
            ("/api-keys", "POST", {"name": "test-key"}),
            ("/sessions", "DELETE", None),
        ]

        try:
            base = target.url.rstrip("/")
            for path, method, body in sensitive_ops:
                url = base + path
                kwargs: Dict[str, Any] = {"headers": headers}
                if body:
                    kwargs["json_body"] = body

                resp = await client.request(method, url, **kwargs)

                # If the sensitive op succeeds without MFA challenge
                if resp.status_code in (200, 201, 202, 204):
                    text = resp.text.lower()
                    # Ensure it's not just a "MFA required" response
                    if not any(kw in text for kw in ["mfa", "2fa", "verify", "otp"]):
                        findings.append(Finding(
                            title=f"Sensitive operation without MFA re-verification: {path}",
                            description=(
                                f"The sensitive endpoint {path} ({method}) succeeded "
                                f"without requiring MFA re-verification. Critical "
                                f"operations should require a fresh MFA challenge."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"URL: {url}\nMethod: {method}\nStatus: {resp.status_code}",
                            remediation=(
                                "Require MFA re-verification for sensitive operations "
                                "like password changes, email changes, API key creation, "
                                "and session management."
                            ),
                            cwe=308,
                            tags=["mfa", "sensitive-operation", "bosskey"],
                        ))
                        break  # one finding is enough
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return findings
