"""
OpenKrump — Excessive data exposure detector.

Identifies API responses returning more fields than the spec declares,
especially sensitive / PII fields.  Maps to OWASP API3:2023.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.excessive_data")


# Fields that should almost never appear in public API responses
_SENSITIVE_FIELDS: Set[str] = {
    "password", "password_hash", "passwd", "secret", "token",
    "access_token", "refresh_token", "api_key", "apikey",
    "ssn", "social_security", "credit_card", "card_number",
    "cvv", "cvc", "pin", "private_key", "secret_key",
    "internal_id", "internal_note", "debug", "stack_trace",
    "trace", "sql", "query", "database_url", "connection_string",
}

_PII_FIELDS: Set[str] = {
    "email", "phone", "phone_number", "address", "date_of_birth",
    "dob", "national_id", "passport", "driver_license", "salary",
    "bank_account", "iban", "routing_number", "ip_address",
}


class ExcessiveDataDetector:
    """Detect responses returning sensitive or unexpected fields."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    def check_response_fields(
        self,
        response_data: Any,
        *,
        expected_fields: Optional[Set[str]] = None,
        target: Optional[Target] = None,
    ) -> List[Finding]:
        """Check a parsed JSON response for excessive / sensitive fields."""
        findings: List[Finding] = []
        if not isinstance(response_data, dict):
            return findings

        actual_fields = self._flatten_keys(response_data)

        # Check for sensitive fields
        sensitive_found = actual_fields & _SENSITIVE_FIELDS
        for field in sorted(sensitive_found):
            findings.append(Finding(
                title=f"Sensitive field '{field}' in API response",
                description=(
                    f"Response contains sensitive field '{field}' which "
                    f"should not be exposed to clients."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"field={field}",
                remediation="Remove sensitive fields from API responses using a DTO or serializer allowlist.",
                cwe=200,
                tags=["excessive-data", "api3", "sensitive"],
            ))

        # Check for PII fields (lower severity — may be expected)
        pii_found = actual_fields & _PII_FIELDS
        for field in sorted(pii_found):
            findings.append(Finding(
                title=f"PII field '{field}' in API response",
                description=(
                    f"Response contains PII field '{field}'. Ensure this "
                    f"is intentional and properly protected."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=f"field={field}",
                remediation="Review whether PII fields should be exposed. Apply field-level access controls.",
                cwe=200,
                tags=["excessive-data", "api3", "pii"],
            ))

        # Check for unexpected fields if schema is provided
        if expected_fields is not None:
            top_level = set(response_data.keys())
            unexpected = top_level - expected_fields
            if unexpected:
                findings.append(Finding(
                    title=f"Unexpected fields in response: {', '.join(sorted(unexpected))}",
                    description=(
                        f"Response contains {len(unexpected)} field(s) not declared "
                        f"in the API schema: {', '.join(sorted(unexpected))}"
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"unexpected={sorted(unexpected)}",
                    remediation="Ensure API responses only include fields declared in the schema.",
                    cwe=200,
                    tags=["excessive-data", "api3", "undeclared"],
                ))

        return findings

    def extract_expected_fields(self, response_schema: Dict[str, Any]) -> Set[str]:
        """Extract expected field names from an OpenAPI response schema."""
        fields: Set[str] = set()
        if not isinstance(response_schema, dict):
            return fields

        properties = response_schema.get("properties", {})
        fields.update(properties.keys())

        # Handle allOf
        for sub in response_schema.get("allOf", []):
            fields.update(self.extract_expected_fields(sub))

        return fields

    @staticmethod
    def _flatten_keys(data: Any, prefix: str = "") -> Set[str]:
        """Recursively extract all field names from a dict."""
        keys: Set[str] = set()
        if isinstance(data, dict):
            for k, v in data.items():
                key = k.lower().strip()
                keys.add(key)
                keys.update(ExcessiveDataDetector._flatten_keys(v, f"{prefix}{k}."))
        elif isinstance(data, list):
            for item in data:
                keys.update(ExcessiveDataDetector._flatten_keys(item, prefix))
        return keys
