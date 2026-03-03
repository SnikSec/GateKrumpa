"""
OpenKrump — response schema validator and security-definition checker.

Validates actual API responses against the schemas declared in the OpenAPI
spec and flags discrepancies as potential security or quality issues.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.validator")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class ValidationIssue:
    """A single schema/security validation issue."""
    endpoint: ParsedEndpoint
    issue_type: str          # "type_mismatch", "missing_field", "extra_field", "no_security", "undocumented_status"
    detail: str
    severity: Severity = Severity.LOW

    @property
    def summary(self) -> str:
        return f"[{self.issue_type}] {self.endpoint.full_id}: {self.detail}"


# ------------------------------------------------------------------
# SchemaValidator
# ------------------------------------------------------------------

class SchemaValidator:
    """
    Validate API responses against OpenAPI schemas and check security definitions.

    Parameters
    ----------
    strict:
        If True, extra response fields not in the schema are flagged.
    """

    def __init__(self, *, strict: bool = False) -> None:
        self.strict = strict

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_response(
        self,
        endpoint: ParsedEndpoint,
        status_code: int,
        body: Any,
    ) -> List[ValidationIssue]:
        """
        Validate *body* (parsed JSON) against the schema declared for
        *status_code* on *endpoint*.
        """
        issues: List[ValidationIssue] = []
        status_key = str(status_code)
        schema = endpoint.response_schemas.get(status_key)

        if schema is None:
            # Check for wildcard keys like "2XX" or "default"
            schema = endpoint.response_schemas.get(f"{status_code // 100}XX")
            if schema is None:
                schema = endpoint.response_schemas.get("default")

        if schema is None:
            issues.append(ValidationIssue(
                endpoint=endpoint,
                issue_type="undocumented_status",
                detail=f"Status {status_code} has no documented response schema.",
                severity=Severity.LOW,
            ))
            return issues

        issues.extend(self._validate_against_schema(endpoint, body, schema, path="$"))
        return issues

    def check_security(self, endpoint: ParsedEndpoint) -> List[ValidationIssue]:
        """Flag endpoints with no security definitions."""
        issues: List[ValidationIssue] = []
        if not endpoint.security:
            issues.append(ValidationIssue(
                endpoint=endpoint,
                issue_type="no_security",
                detail="Endpoint has no security definitions.",
                severity=Severity.MEDIUM,
            ))
        return issues

    def check_deprecated(self, endpoint: ParsedEndpoint) -> List[ValidationIssue]:
        """Flag deprecated endpoints that are still accessible."""
        if endpoint.deprecated:
            return [ValidationIssue(
                endpoint=endpoint,
                issue_type="deprecated",
                detail="Endpoint is marked deprecated.",
                severity=Severity.INFO,
            )]
        return []

    def issues_to_findings(
        self,
        issues: List[ValidationIssue],
        target: Target,
    ) -> List[Finding]:
        """Convert validation issues to core Finding objects."""
        findings: List[Finding] = []
        for issue in issues:
            findings.append(Finding(
                title=f"API schema issue: {issue.issue_type} on {issue.endpoint.full_id}",
                description=issue.detail,
                severity=issue.severity,
                target=target,
                tags=["openapi", issue.issue_type],
            ))
        return findings

    # ------------------------------------------------------------------
    # Schema walking
    # ------------------------------------------------------------------

    def _validate_against_schema(
        self,
        endpoint: ParsedEndpoint,
        value: Any,
        schema: Dict[str, Any],
        path: str,
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        schema_type = schema.get("type")

        if schema_type == "object":
            issues.extend(self._validate_object(endpoint, value, schema, path))
        elif schema_type == "array":
            issues.extend(self._validate_array(endpoint, value, schema, path))
        elif schema_type:
            issues.extend(self._validate_primitive(endpoint, value, schema_type, path))

        return issues

    def _validate_object(
        self,
        endpoint: ParsedEndpoint,
        value: Any,
        schema: Dict[str, Any],
        path: str,
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        if not isinstance(value, dict):
            issues.append(ValidationIssue(
                endpoint=endpoint,
                issue_type="type_mismatch",
                detail=f"{path}: expected object, got {type(value).__name__}",
            ))
            return issues

        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        # Check required fields
        for req_field in required:
            if req_field not in value:
                issues.append(ValidationIssue(
                    endpoint=endpoint,
                    issue_type="missing_field",
                    detail=f"{path}.{req_field}: required field missing",
                    severity=Severity.MEDIUM,
                ))

        # Check field types
        for prop_name, prop_schema in properties.items():
            if prop_name in value:
                issues.extend(self._validate_against_schema(
                    endpoint, value[prop_name], prop_schema,
                    f"{path}.{prop_name}",
                ))

        # Strict: flag extra fields
        if self.strict and properties:
            for key in value:
                if key not in properties:
                    issues.append(ValidationIssue(
                        endpoint=endpoint,
                        issue_type="extra_field",
                        detail=f"{path}.{key}: field not in schema",
                        severity=Severity.INFO,
                    ))

        return issues

    def _validate_array(
        self,
        endpoint: ParsedEndpoint,
        value: Any,
        schema: Dict[str, Any],
        path: str,
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        if not isinstance(value, list):
            issues.append(ValidationIssue(
                endpoint=endpoint,
                issue_type="type_mismatch",
                detail=f"{path}: expected array, got {type(value).__name__}",
            ))
            return issues

        item_schema = schema.get("items", {})
        if item_schema and value:
            # Validate first element as representative
            issues.extend(self._validate_against_schema(
                endpoint, value[0], item_schema, f"{path}[0]",
            ))

        return issues

    def _validate_primitive(
        self,
        endpoint: ParsedEndpoint,
        value: Any,
        expected_type: str,
        path: str,
    ) -> List[ValidationIssue]:
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
        }
        expected = type_map.get(expected_type)
        if expected and not isinstance(value, expected):
            return [ValidationIssue(
                endpoint=endpoint,
                issue_type="type_mismatch",
                detail=f"{path}: expected {expected_type}, got {type(value).__name__}",
            )]
        return []
