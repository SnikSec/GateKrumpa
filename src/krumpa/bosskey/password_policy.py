"""
BossKey — Password policy testing.

Tests password complexity enforcement: short passwords, common passwords,
lack of character-class requirements, and overly long password handling.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.bosskey.password_policy")


# Subset of "rockyou top 20" + obvious weak passwords
COMMON_PASSWORDS: List[str] = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "admin", "Admin123", "P@ssw0rd", "Welcome1", "changeme",
]

# Passwords probing specific complexity rules
POLICY_PROBES: List[Dict[str, Any]] = [
    {"password": "a",              "label": "1-char password",        "expect_reject": True},
    {"password": "ab",             "label": "2-char password",        "expect_reject": True},
    {"password": "abcdef",         "label": "6-char no digits/upper", "expect_reject": True},
    {"password": "abcdefgh",       "label": "8-char lowercase only",  "expect_reject": True},
    {"password": "ABCDEFGH",       "label": "8-char uppercase only",  "expect_reject": True},
    {"password": "12345678",       "label": "8-char digits only",     "expect_reject": True},
    {"password": "aaaa" * 65,      "label": "260-char password",      "expect_reject": False},
    {"password": "Str0ng!Pwd#9",   "label": "strong password",        "expect_reject": False},
    {"password": "P@$$w0rd!Xyz",   "label": "complex password",       "expect_reject": False},
]


@dataclass
class PasswordPolicyResult:
    """Outcome of a single password probe."""
    password_label: str
    accepted: bool
    expected_reject: bool
    status_code: int = 0
    response_snippet: str = ""

    @property
    def is_weakness(self) -> bool:
        """A weakness if a password expected to be rejected was accepted."""
        return self.expected_reject and self.accepted


class PasswordPolicyTester:
    """
    Test the target's password policy by submitting various password
    values and observing whether they are accepted or rejected.
    """

    # Status codes / patterns that indicate acceptance
    _ACCEPT_CODES = {200, 201, 302, 303}
    _REJECT_PATTERNS = [
        "password", "too short", "too weak", "complexity", "requirements",
        "must contain", "invalid", "policy", "strength",
    ]

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        username_field: str = "username",
        password_field: str = "password",
        test_username: str = "gatekrumpa_test_user",
        common_passwords: Optional[List[str]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._username_field = username_field
        self._password_field = password_field
        self._test_username = test_username
        self._common_passwords = common_passwords or COMMON_PASSWORDS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test(self, target: Target) -> List[Finding]:
        """Run all password-policy probes against *target* (registration or password-change endpoint)."""
        findings: List[Finding] = []

        # Phase 1: Common / weak password spray
        common_results = await self._test_common_passwords(target)
        accepted = [r for r in common_results if r.is_weakness]
        if accepted:
            labels = ", ".join(r.password_label for r in accepted[:5])
            findings.append(Finding(
                title="Weak passwords accepted",
                description=(
                    f"{len(accepted)} of {len(common_results)} common/weak passwords "
                    f"were accepted by {target.url}: {labels}"
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(
                    f"  {r.password_label}: status={r.status_code}"
                    for r in accepted[:10]
                ),
                remediation=(
                    "Enforce a password policy requiring minimum length (≥12), "
                    "mixed case, digits, and special characters. Block passwords "
                    "appearing in breach databases (e.g. HaveIBeenPwned)."
                ),
                cwe=521,
                tags=["password", "policy", "auth"],
            ))

        # Phase 2: Complexity probes
        probe_results = await self._test_policy_probes(target)
        policy_weak = [r for r in probe_results if r.is_weakness]
        if policy_weak:
            labels = ", ".join(r.password_label for r in policy_weak)
            findings.append(Finding(
                title="Insufficient password complexity enforcement",
                description=(
                    f"Password policy allows: {labels}. "
                    f"Endpoint: {target.url}"
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(
                    f"  {r.password_label}: accepted (status={r.status_code})"
                    for r in policy_weak
                ),
                remediation=(
                    "Require at least 8 characters with mixed character classes. "
                    "Reject passwords that are all-lowercase, all-digits, or trivially short."
                ),
                cwe=521,
                tags=["password", "complexity", "auth"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Static analysis (no HTTP)
    # ------------------------------------------------------------------

    def analyse_policy_config(
        self,
        policy: Dict[str, Any],
        target: Target,
    ) -> List[Finding]:
        """
        Check a declarative policy dict (e.g. from a config dump) for weaknesses.

        Expected keys: min_length, require_uppercase, require_digit,
                       require_special, max_length
        """
        findings: List[Finding] = []
        min_len = policy.get("min_length", 0)
        if min_len < 8:
            findings.append(Finding(
                title=f"Low minimum password length ({min_len})",
                description=f"Minimum password length is {min_len}, should be ≥8.",
                severity=Severity.MEDIUM,
                target=target,
                cwe=521,
                tags=["password", "policy", "config"],
            ))

        for key in ("require_uppercase", "require_digit", "require_special"):
            if not policy.get(key, False):
                findings.append(Finding(
                    title=f"Password policy missing: {key.replace('_', ' ')}",
                    description=f"Policy does not enforce {key.replace('_', ' ')}.",
                    severity=Severity.LOW,
                    target=target,
                    cwe=521,
                    tags=["password", "policy", "config"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _test_common_passwords(self, target: Target) -> List[PasswordPolicyResult]:
        results: List[PasswordPolicyResult] = []
        for pwd in self._common_passwords:
            result = await self._submit_password(target, pwd, label=pwd, expect_reject=True)
            results.append(result)
        return results

    async def _test_policy_probes(self, target: Target) -> List[PasswordPolicyResult]:
        results: List[PasswordPolicyResult] = []
        for probe in POLICY_PROBES:
            result = await self._submit_password(
                target,
                probe["password"],
                label=probe["label"],
                expect_reject=probe["expect_reject"],
            )
            results.append(result)
        return results

    async def _submit_password(
        self, target: Target, password: str, *, label: str, expect_reject: bool,
    ) -> PasswordPolicyResult:
        """POST the password and determine accepted/rejected."""
        client = self._client
        if client is None:
            client = HttpClient(timeout=10.0, retries=0)

        try:
            body = {
                self._username_field: self._test_username,
                self._password_field: password,
            }
            resp = await client.request(
                "POST", target.url,
                json_body=body,
                headers={"Content-Type": "application/json"},
            )
            accepted = self._is_accepted(resp)
            snippet = (resp.text or "")[:200]

            return PasswordPolicyResult(
                password_label=label,
                accepted=accepted,
                expected_reject=expect_reject,
                status_code=resp.status_code,
                response_snippet=snippet,
            )
        except Exception as exc:
            logger.debug("Error submitting password probe '%s': %s", label, exc)
            return PasswordPolicyResult(
                password_label=label,
                accepted=False,
                expected_reject=expect_reject,
            )
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    def _is_accepted(self, resp: Any) -> bool:
        """Heuristic: treat HTTP 2xx/3xx as accepted unless body rejects."""
        code = getattr(resp, "status_code", 0)
        text = (getattr(resp, "text", "") or "").lower()

        if code in self._ACCEPT_CODES:
            # Check if the response body actually indicates rejection
            for pattern in self._REJECT_PATTERNS:
                if pattern in text:
                    return False
            return True
        return False
