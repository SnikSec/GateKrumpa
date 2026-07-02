"""
WaaaghLogic — Mass assignment testing.

Test for mass assignment (OWASP API #6) by injecting unexpected fields
(role, isAdmin, price, etc.) and checking if the server accepts them.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.mass_assignment")


# Fields that should typically be server-only
DANGEROUS_FIELDS: List[Dict[str, Any]] = [
    {"name": "role", "values": ["admin", "superadmin", "root"], "severity": "critical"},
    {"name": "isAdmin", "values": [True, 1, "true"], "severity": "critical"},
    {"name": "is_admin", "values": [True, 1], "severity": "critical"},
    {"name": "admin", "values": [True, 1], "severity": "critical"},
    {"name": "permissions", "values": [["*"], ["admin"]], "severity": "critical"},
    {"name": "privilege", "values": ["admin", "elevated"], "severity": "critical"},
    {"name": "user_type", "values": ["admin", "staff"], "severity": "high"},
    {"name": "account_type", "values": ["premium", "enterprise"], "severity": "high"},
    {"name": "price", "values": [0, -1, 0.01], "severity": "high"},
    {"name": "total", "values": [0, -100], "severity": "high"},
    {"name": "discount", "values": [100, 99.99], "severity": "high"},
    {"name": "balance", "values": [999999, 0], "severity": "high"},
    {"name": "verified", "values": [True, 1], "severity": "medium"},
    {"name": "email_verified", "values": [True], "severity": "medium"},
    {"name": "active", "values": [True, False], "severity": "medium"},
    {"name": "status", "values": ["active", "approved"], "severity": "medium"},
    {"name": "created_at", "values": ["2020-01-01"], "severity": "low"},
    {"name": "updated_at", "values": ["2020-01-01"], "severity": "low"},
    {"name": "id", "values": [1, 0, 9999], "severity": "medium"},
    {"name": "user_id", "values": [1, 0], "severity": "high"},
]


@dataclass
class MassAssignmentResult(HttpClientMixin):
    """Result of injecting a single extra field."""
    field_name: str
    injected_value: Any
    accepted: bool = False
    reflected: bool = False
    status_code: int = 0
    response_snippet: str = ""


class MassAssignmentTester(HttpClientMixin):
    """
    Test endpoints for mass assignment by injecting extra fields
    into request bodies and checking if they're accepted.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        extra_fields: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._fields = extra_fields or DANGEROUS_FIELDS

    async def test(self, target: Target) -> List[Finding]:
        """Inject extra fields into the target's body and report accepted ones."""
        findings: List[Finding] = []
        base_body = self._get_base_body(target)
        if not base_body:
            return findings

        results = await self._test_fields(target, base_body)
        critical = [r for r in results if r.accepted and self._get_severity(r.field_name) == "critical"]
        high = [r for r in results if r.accepted and self._get_severity(r.field_name) == "high"]
        other = [r for r in results if r.accepted and self._get_severity(r.field_name) not in ("critical", "high")]

        if critical:
            names = ", ".join(r.field_name for r in critical)
            findings.append(Finding(
                title="Mass assignment — privilege escalation fields accepted",
                description=(
                    f"Privilege-related fields [{names}] were accepted by {target.url}. "
                    f"This may allow attackers to elevate privileges."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence="\n".join(
                    f"  {r.field_name}={r.injected_value} → status {r.status_code}"
                    for r in critical
                ),
                remediation="Use an allowlist of permitted fields. Never bind user input directly to model attributes.",
                cwe=915,
                tags=["mass-assignment", "privilege-escalation", "api"],
            ))

        if high:
            names = ", ".join(r.field_name for r in high)
            findings.append(Finding(
                title="Mass assignment — sensitive fields accepted",
                description=f"Fields [{names}] were accepted by {target.url}.",
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(
                    f"  {r.field_name}={r.injected_value} → status {r.status_code}"
                    for r in high
                ),
                remediation="Explicitly allowlist accepted fields for each endpoint.",
                cwe=915,
                tags=["mass-assignment", "api"],
            ))

        if other:
            names = ", ".join(r.field_name for r in other)
            findings.append(Finding(
                title="Mass assignment — extra fields accepted",
                description=f"Unexpected fields [{names}] were accepted by {target.url}.",
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(
                    f"  {r.field_name}={r.injected_value} → status {r.status_code}"
                    for r in other
                ),
                cwe=915,
                tags=["mass-assignment", "api"],
            ))

        return findings

    def get_dangerous_fields(self) -> List[Dict[str, Any]]:
        return list(self._fields)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _test_fields(
        self, target: Target, base_body: Dict[str, Any],
    ) -> List[MassAssignmentResult]:
        results: List[MassAssignmentResult] = []
        client = self._get_client()

        try:
            # Get baseline response
            baseline = await client.request(
                target.method or "POST", target.url,
                json_body=base_body,
                headers={"Content-Type": "application/json"},
            )
            baseline_code = getattr(baseline, "status_code", 200)

            for field_spec in self._fields:
                field_name = field_spec["name"]
                if field_name in base_body:
                    continue  # already present, skip

                for value in field_spec["values"]:
                    mutated = dict(base_body)
                    mutated[field_name] = value

                    try:
                        resp = await client.request(
                            target.method or "POST", target.url,
                            json_body=mutated,
                            headers={"Content-Type": "application/json"},
                        )
                        code = getattr(resp, "status_code", 0)
                        text = (getattr(resp, "text", "") or "")[:500]

                        accepted = code in (200, 201, 204) or code == baseline_code
                        reflected = str(value).lower() in text.lower()

                        results.append(MassAssignmentResult(
                            field_name=field_name,
                            injected_value=value,
                            accepted=accepted,
                            reflected=reflected,
                            status_code=code,
                            response_snippet=text[:200],
                        ))

                        if accepted:
                            break  # one accepted value per field is enough
                    except Exception as exc:
                        logger.debug("Mass assignment test error for %s: %s", field_name, exc)
        finally:
            self._maybe_close(client)

        return results

    def _get_severity(self, field_name: str) -> str:
        for spec in self._fields:
            if spec["name"] == field_name:
                return spec.get("severity", "medium")
        return "medium"

    @staticmethod
    def _get_base_body(target: Target) -> Optional[Dict[str, Any]]:
        if target.body:
            try:
                parsed = json.loads(target.body)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
        return target.metadata.get("body_json")

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
