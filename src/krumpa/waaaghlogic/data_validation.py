"""
WaaaghLogic — Data validation bypass testing.

Negative quantities, type confusion, null injection, boundary testing
to find business logic flaws from invalid data processing.

CWE-20: Improper Input Validation
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.data_validation")


# Payloads organised by bypass category
_NEGATIVE_PAYLOADS: List[Dict[str, Any]] = [
    {"label": "Negative quantity", "field_hint": "quantity", "value": -1},
    {"label": "Negative price", "field_hint": "price", "value": -100.00},
    {"label": "Negative amount", "field_hint": "amount", "value": -9999},
    {"label": "Zero quantity", "field_hint": "quantity", "value": 0},
    {"label": "Zero price", "field_hint": "price", "value": 0},
]

_TYPE_CONFUSION_PAYLOADS: List[Dict[str, Any]] = [
    {"label": "String instead of int", "value": "abc"},
    {"label": "Boolean true instead of int", "value": True},
    {"label": "Boolean false instead of int", "value": False},
    {"label": "Array instead of scalar", "value": [1, 2, 3]},
    {"label": "Object instead of scalar", "value": {"key": "val"}},
    {"label": "Float instead of int", "value": 1.9999999},
    {"label": "Null instead of required", "value": None},
    {"label": "Empty string instead of required", "value": ""},
    {"label": "Nested null", "value": {"inner": None}},
]

_NULL_INJECTION_PAYLOADS: List[Dict[str, str]] = [
    {"label": "Null byte in string", "value": "test\x00admin"},
    {"label": "Null byte mid-email", "value": "user\x00@evil.com"},
    {"label": "Null byte file extension", "value": "file.txt\x00.exe"},
    {"label": "URL-encoded null", "value": "test%00admin"},
    {"label": "Unicode null", "value": "test\u0000admin"},
]


@dataclass
class ValidationResult:
    """Result of a single validation bypass attempt."""
    label: str
    field_name: str
    injected_value: Any
    accepted: bool = False
    status_code: int = 0
    response_snippet: str = ""


class DataValidationTester:
    """
    Test endpoints for data validation bypass:
      1. Negative value injection (quantities, prices, amounts)
      2. Type confusion (string→int, array→scalar, null→required)
      3. Null byte injection
      4. Special value testing (NaN, Infinity, undefined)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def test(self, target: Target) -> List[Finding]:
        """Run all data validation tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Negative value injection ---
            neg_findings = await self._test_negative_values(client, target)
            findings.extend(neg_findings)

            # --- 2. Type confusion ---
            type_findings = await self._test_type_confusion(client, target)
            findings.extend(type_findings)

            # --- 3. Null injection ---
            null_findings = await self._test_null_injection(client, target)
            findings.extend(null_findings)

            # --- 4. Special values ---
            special_findings = await self._test_special_values(client, target)
            findings.extend(special_findings)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_negative_values(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Inject negative quantities, prices, amounts."""
        findings: List[Finding] = []

        for payload in _NEGATIVE_PAYLOADS:
            field_name = payload["field_hint"]
            value = payload["value"]
            body = {field_name: value}

            try:
                resp = await client.request(
                    target.method or "POST", target.url, json_body=body,
                )
                if resp.status_code in (200, 201, 202, 204):
                    findings.append(Finding(
                        title=f"Negative value accepted: {payload['label']} on {target.url}",
                        description=(
                            f"The endpoint accepted {field_name}={value}. "
                            f"Negative values in financial/quantity fields can lead "
                            f"to balance manipulation, inventory corruption, or "
                            f"refund fraud."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"Field: {field_name}={value}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response: {resp.text[:200]}"
                        ),
                        remediation=(
                            "Validate that numeric fields are within expected ranges. "
                            "Use unsigned integers or explicit min-value=0 constraints. "
                            "Enforce business rules server-side."
                        ),
                        cwe=20,
                        tags=["data-validation", "negative-value", "waaaghlogic"],
                    ))
                    break  # one finding per category is enough
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_type_confusion(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send wrong types to trigger unexpected server behavior."""
        findings: List[Finding] = []
        test_fields = ["id", "quantity", "amount", "count", "page", "limit"]

        for field_name in test_fields:
            for payload in _TYPE_CONFUSION_PAYLOADS:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    # 500 errors often indicate un-handled type confusion
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Type confusion causes server error on {target.url}",
                            description=(
                                f"Sending {payload['label']} for field '{field_name}' "
                                f"triggered a {resp.status_code} server error. "
                                f"This indicates missing input type validation and "
                                f"may expose error details or crash the service."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}={json.dumps(payload['value'])}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Validate input types before processing. Use schema "
                                "validation (e.g., JSON Schema, Pydantic) on all endpoints."
                            ),
                            cwe=843,
                            tags=["data-validation", "type-confusion", "waaaghlogic"],
                        ))
                        return findings  # one finding is enough
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_null_injection(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Inject null bytes to bypass validation."""
        findings: List[Finding] = []
        test_fields = ["name", "email", "filename", "path", "value"]

        for field_name in test_fields:
            for payload in _NULL_INJECTION_PAYLOADS:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code in (200, 201, 202, 204):
                        # Check if null byte wasn't stripped
                        if "\x00" in resp.text or "%00" in resp.text:
                            findings.append(Finding(
                                title=f"Null byte injection accepted on {target.url}",
                                description=(
                                    f"The endpoint accepted a null byte in '{field_name}' "
                                    f"({payload['label']}). Null bytes can truncate strings "
                                    f"in C-based backends, bypass file extension checks, "
                                    f"or confuse input validators."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=(
                                    f"Field: {field_name}\n"
                                    f"Payload: {payload['label']}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Strip or reject null bytes from all input. "
                                    "Use parameterized queries and safe string handling."
                                ),
                                cwe=626,
                                tags=["data-validation", "null-injection", "waaaghlogic"],
                            ))
                            return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_special_values(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test NaN, Infinity, and other special numeric values."""
        findings: List[Finding] = []
        special_values = [
            ("NaN", float("nan")),
            ("Infinity", float("inf")),
            ("-Infinity", float("-inf")),
        ]
        test_fields = ["price", "amount", "quantity", "total"]

        for field_name in test_fields:
            for label, value in special_values:
                # JSON doesn't support NaN/Infinity natively,
                # but some parsers accept them
                body_str = f'{{"{field_name}": {label}}}'
                try:
                    resp = await client.request(
                        target.method or "POST", target.url,
                        headers={"Content-Type": "application/json"},
                        body=body_str.encode(),
                    )
                    if resp.status_code in (200, 201, 202, 204):
                        findings.append(Finding(
                            title=f"Special numeric value {label} accepted on {target.url}",
                            description=(
                                f"The endpoint accepted {label} for field '{field_name}'. "
                                f"Special IEEE 754 values can cause unexpected behavior "
                                f"in arithmetic operations (NaN comparisons always false, "
                                f"Infinity overflow)."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}={label}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Reject NaN, Infinity, and -Infinity in numeric fields. "
                                "Use strict JSON parsing without extended number support."
                            ),
                            cwe=20,
                            tags=["data-validation", "special-value", "waaaghlogic"],
                        ))
                        return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings
