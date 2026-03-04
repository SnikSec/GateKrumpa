"""
Registration flow testing — duplicate registration, email bypass,
privilege assignment, CAPTCHA detection, field injection.

OWASP: WSTG-ATHN-02 (Testing for Default Credentials / Registration)
CWE-287: Improper Authentication
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger(__name__)

# Common email bypass variations
_EMAIL_BYPASSES = [
    ("plus-tag", "test+admin@example.com"),
    ("dot-variation", "t.e.s.t@example.com"),
    ("case-variation", "TEST@EXAMPLE.COM"),
    ("trailing-dot", "test@example.com."),
    ("null-byte", "test%00@example.com"),
    ("double-at", "test@@example.com"),
    ("space-prefix", " test@example.com"),
    ("space-suffix", "test@example.com "),
]

# Fields that attackers try to inject during registration
_PRIVILEGE_FIELDS: List[Dict[str, Any]] = [
    {"field": "role", "values": ["admin", "administrator", "superuser"]},
    {"field": "is_admin", "values": [True, 1, "true"]},
    {"field": "isAdmin", "values": [True, 1, "true"]},
    {"field": "admin", "values": [True, 1, "true"]},
    {"field": "privilege", "values": ["admin", "elevated"]},
    {"field": "type", "values": ["admin", "staff", "internal"]},
    {"field": "user_type", "values": ["admin", "staff"]},
    {"field": "level", "values": [99, 100, "admin"]},
    {"field": "permissions", "values": [["*"], ["admin"], ["all"]]},
    {"field": "verified", "values": [True, 1]},
    {"field": "email_verified", "values": [True, 1]},
    {"field": "active", "values": [True, 1]},
]


class RegistrationTester(HttpClientMixin):
    """
    Test registration flows for:
      1. Duplicate account creation (same email, different casing/formatting)
      2. Email bypass (case, plus-tags, dots, null bytes)
      3. Privilege escalation via extra fields (role, isAdmin, etc.)
      4. Missing CAPTCHA / rate-limiting
      5. User enumeration via registration endpoint
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        base_email: str = "krumpa-test@example.com",
        base_password: str = "KrumpaT3st!Passw0rd",
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._base_email = base_email
        self._base_password = base_password

    async def test(self, target: Target) -> List[Finding]:
        """Run all registration flow tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Duplicate registration detection ----------------------
            dup_finding = await self._test_duplicate_registration(client, target)
            if dup_finding:
                findings.append(dup_finding)

            # --- 2. Email bypass testing ----------------------------------
            bypass_findings = await self._test_email_bypasses(client, target)
            findings.extend(bypass_findings)

            # --- 3. Privilege injection -----------------------------------
            priv_findings = await self._test_privilege_injection(client, target)
            findings.extend(priv_findings)

            # --- 4. User enumeration via registration ---------------------
            enum_finding = await self._test_user_enumeration(client, target)
            if enum_finding:
                findings.append(enum_finding)

            # --- 5. Rate-limiting check -----------------------------------
            rate_finding = await self._test_rate_limit(client, target)
            if rate_finding:
                findings.append(rate_finding)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_duplicate_registration(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Try registering the same email twice."""
        body = self._build_reg_body(self._base_email)
        statuses = []
        try:
            for _ in range(2):
                resp = await client.request("POST", target.url, json_body=body)
                statuses.append(resp.status_code)

            # If both succeed, duplicates may be accepted
            if all(s in (200, 201, 202) for s in statuses):
                return Finding(
                    title=f"Duplicate registration accepted on {target.url}",
                    description=(
                        "Two registration requests with the same email both "
                        "returned success. This may allow account squatting, "
                        "duplicate entries, or data integrity issues."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Responses: {statuses}",
                    remediation=(
                        "Enforce unique email constraint at the database level. "
                        "Return an appropriate error for duplicate registrations."
                    ),
                    cwe=287,
                    tags=["registration", "duplicate", "bosskey"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _test_email_bypasses(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test email bypass variants (plus-tags, case, dots, etc.)."""
        findings: List[Finding] = []
        try:
            for name, email in _EMAIL_BYPASSES:
                body = self._build_reg_body(email)
                resp = await client.request("POST", target.url, json_body=body)
                if resp.status_code in (200, 201, 202):
                    findings.append(Finding(
                        title=f"Email bypass accepted ({name}) on {target.url}",
                        description=(
                            f"Registration with email bypass variant '{name}' "
                            f"(email: {email}) was accepted. This can allow "
                            f"duplicate accounts using email normalization tricks."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"Bypass: {name}, Email: {email}, Status: {resp.status_code}",
                        remediation=(
                            "Normalize email addresses before uniqueness checks: "
                            "lowercase, strip dots from Gmail, remove plus-tags, "
                            "trim whitespace."
                        ),
                        cwe=287,
                        tags=["registration", "email-bypass", "bosskey"],
                    ))
                    break  # one finding is enough
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return findings

    async def _test_privilege_injection(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Inject privilege fields (role, isAdmin, etc.) in registration body."""
        findings: List[Finding] = []
        try:
            for field_spec in _PRIVILEGE_FIELDS:
                field_name = field_spec["field"]
                for value in field_spec["values"]:
                    body = self._build_reg_body(
                        f"krumpa-priv-{field_name}@example.com",
                    )
                    body[field_name] = value

                    resp = await client.request("POST", target.url, json_body=body)
                    if resp.status_code in (200, 201, 202):
                        # Check if the injected field appears in response
                        resp_text = resp.text.lower()
                        if (
                            str(value).lower() in resp_text
                            or field_name in resp_text
                        ):
                            findings.append(Finding(
                                title=f"Privilege injection via '{field_name}' on {target.url}",
                                description=(
                                    f"Injecting '{field_name}={value}' in the registration "
                                    f"request was accepted and reflected in the response. "
                                    f"This may allow self-assignment of elevated privileges."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=(
                                    f"Field: {field_name}={value}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Server-side allowlisting of accepted registration fields. "
                                    "Never allow clients to set role/privilege fields. "
                                    "Use DTOs or explicit field mapping."
                                ),
                                cwe=269,
                                tags=["registration", "privilege-injection", "mass-assignment", "bosskey"],
                            ))
                            return findings  # one critical finding is enough
                    break  # one value per field is enough
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return findings

    async def _test_user_enumeration(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Check if registration reveals existing accounts."""
        try:
            # Register with a likely-existing email
            body_existing = self._build_reg_body("admin@example.com")
            resp_existing = await client.request("POST", target.url, json_body=body_existing)

            body_new = self._build_reg_body("definitely-new-user-xyz@example.com")
            resp_new = await client.request("POST", target.url, json_body=body_new)

            if resp_existing.status_code != resp_new.status_code:
                return Finding(
                    title=f"User enumeration via registration on {target.url}",
                    description=(
                        f"Different response codes for existing ({resp_existing.status_code}) "
                        f"vs. new ({resp_new.status_code}) email addresses reveal "
                        f"which accounts are registered."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Existing email: {resp_existing.status_code}\n"
                        f"New email: {resp_new.status_code}"
                    ),
                    remediation=(
                        "Return identical responses for both existing and new emails. "
                        "Send confirmation emails for both cases."
                    ),
                    cwe=204,
                    tags=["user-enumeration", "registration", "bosskey"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass
        return None

    async def _test_rate_limit(
        self, client: HttpClient, target: Target,
    ) -> Optional[Finding]:
        """Rapid-fire registration requests to check for rate-limiting."""
        success_count = 0
        try:
            for i in range(10):
                body = self._build_reg_body(f"krumpa-rate-{i}@example.com")
                resp = await client.request("POST", target.url, json_body=body)
                if resp.status_code in (200, 201, 202, 204):
                    success_count += 1
                elif resp.status_code == 429:
                    return None  # rate-limiting is present
        except (httpx.HTTPError, OSError, ValueError):
            pass

        if success_count >= 10:
            return Finding(
                title=f"No rate-limiting on registration at {target.url}",
                description=(
                    f"Sent 10 rapid registration requests and all succeeded. "
                    f"No rate-limiting or CAPTCHA detected, enabling automated "
                    f"account creation for spam or abuse."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Success: {success_count}/10 requests",
                remediation=(
                    "Implement rate-limiting and CAPTCHA on registration endpoints. "
                    "Limit registrations per IP and per email domain."
                ),
                cwe=307,
                tags=["rate-limit", "registration", "bosskey"],
            )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_reg_body(self, email: str) -> Dict[str, Any]:
        """Build a minimal registration request body."""
        return {
            "email": email,
            "password": self._base_password,
            "username": email.split("@")[0],
            "name": "Krumpa Test",
        }
