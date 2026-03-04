"""
OpenKrump — Full response schema validation.

Complete JSON Schema validation of API responses: types, required fields,
enum values, format constraints, min/max, pattern matching.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.schema_validator")


@dataclass
class SchemaViolation:
    """A single schema validation failure."""
    path: str  # JSON path to the failing field
    message: str
    expected: str = ""
    actual: str = ""
    severity: Severity = Severity.LOW


class ResponseSchemaValidator:
    """
    Validate API responses against JSON Schema definitions from the spec.
    """

    def __init__(self, *, strict: bool = False) -> None:
        self._strict = strict

    def validate(
        self,
        schema: Dict[str, Any],
        data: Any,
        target: Target,
        *,
        path: str = "$",
    ) -> List[Finding]:
        """Validate *data* against *schema* and return findings."""
        violations = self._check(schema, data, path)
        return self._to_findings(violations, target)

    def check(
        self,
        schema: Dict[str, Any],
        data: Any,
        *,
        path: str = "$",
    ) -> List[SchemaViolation]:
        """Return raw violations without converting to findings."""
        return self._check(schema, data, path)

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------

    def _check(
        self,
        schema: Dict[str, Any],
        data: Any,
        path: str,
    ) -> List[SchemaViolation]:
        violations: List[SchemaViolation] = []

        if not schema:
            return violations

        # Type check
        expected_type = schema.get("type")
        if expected_type:
            violations.extend(self._check_type(expected_type, data, path))

        # Required fields
        if schema.get("required") and isinstance(data, dict):
            for req_field in schema["required"]:
                if req_field not in data:
                    violations.append(SchemaViolation(
                        path=f"{path}.{req_field}",
                        message=f"Missing required field '{req_field}'",
                        expected="present",
                        actual="missing",
                        severity=Severity.MEDIUM,
                    ))

        # Enum
        if "enum" in schema and data not in schema["enum"]:
            violations.append(SchemaViolation(
                path=path,
                message=f"Value not in enum: {schema['enum']}",
                expected=str(schema["enum"]),
                actual=str(data),
            ))

        # Format
        fmt = schema.get("format")
        if fmt and isinstance(data, str):
            violations.extend(self._check_format(fmt, data, path))

        # String constraints
        if isinstance(data, str):
            if "minLength" in schema and len(data) < schema["minLength"]:
                violations.append(SchemaViolation(
                    path=path,
                    message=f"String too short (min {schema['minLength']})",
                    expected=f"minLength={schema['minLength']}",
                    actual=f"length={len(data)}",
                ))
            if "maxLength" in schema and len(data) > schema["maxLength"]:
                violations.append(SchemaViolation(
                    path=path,
                    message=f"String too long (max {schema['maxLength']})",
                    expected=f"maxLength={schema['maxLength']}",
                    actual=f"length={len(data)}",
                ))
            if "pattern" in schema:
                if not re.search(schema["pattern"], data):
                    violations.append(SchemaViolation(
                        path=path,
                        message=f"String doesn't match pattern: {schema['pattern']}",
                        expected=f"pattern={schema['pattern']}",
                        actual=data[:50],
                    ))

        # Numeric constraints
        if isinstance(data, (int, float)):
            if "minimum" in schema and data < schema["minimum"]:
                violations.append(SchemaViolation(path=path, message=f"Below minimum ({schema['minimum']})"))
            if "maximum" in schema and data > schema["maximum"]:
                violations.append(SchemaViolation(path=path, message=f"Above maximum ({schema['maximum']})"))
            if "exclusiveMinimum" in schema and data <= schema["exclusiveMinimum"]:
                violations.append(SchemaViolation(path=path, message=f"At or below exclusive minimum ({schema['exclusiveMinimum']})"))
            if "exclusiveMaximum" in schema and data >= schema["exclusiveMaximum"]:
                violations.append(SchemaViolation(path=path, message=f"At or above exclusive maximum ({schema['exclusiveMaximum']})"))
            if "multipleOf" in schema and schema["multipleOf"] != 0:
                if data % schema["multipleOf"] != 0:
                    violations.append(SchemaViolation(path=path, message=f"Not a multiple of {schema['multipleOf']}"))

        # Object properties
        if isinstance(data, dict) and "properties" in schema:
            props = schema["properties"]
            for prop_name, prop_schema in props.items():
                if prop_name in data:
                    violations.extend(
                        self._check(prop_schema, data[prop_name], f"{path}.{prop_name}")
                    )

            # Additional properties check (strict mode)
            if self._strict and schema.get("additionalProperties") is False:
                extra = set(data.keys()) - set(props.keys())
                for key in extra:
                    violations.append(SchemaViolation(
                        path=f"{path}.{key}",
                        message=f"Unexpected additional property '{key}'",
                        severity=Severity.LOW,
                    ))

        # Array items
        if isinstance(data, list) and "items" in schema:
            if "minItems" in schema and len(data) < schema["minItems"]:
                violations.append(SchemaViolation(path=path, message=f"Array too short (min {schema['minItems']})"))
            if "maxItems" in schema and len(data) > schema["maxItems"]:
                violations.append(SchemaViolation(path=path, message=f"Array too long (max {schema['maxItems']})"))

            item_schema = schema["items"]
            for i, item in enumerate(data):
                violations.extend(self._check(item_schema, item, f"{path}[{i}]"))

        # Nullable
        if data is None and not schema.get("nullable", False) and expected_type:
            violations.append(SchemaViolation(
                path=path,
                message="Null value for non-nullable field",
                severity=Severity.MEDIUM,
            ))

        return violations

    # ------------------------------------------------------------------
    # Type checking
    # ------------------------------------------------------------------

    @staticmethod
    def _check_type(
        expected: str, data: Any, path: str,
    ) -> List[SchemaViolation]:
        if data is None:
            return []  # handled by nullable check

        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        expected_types = type_map.get(expected)
        if expected_types and not isinstance(data, expected_types):
            # Special case: integer passed as float with no decimal part
            if expected == "integer" and isinstance(data, float) and data == int(data):
                return []
            return [SchemaViolation(
                path=path,
                message=f"Wrong type: expected {expected}, got {type(data).__name__}",
                expected=expected,
                actual=type(data).__name__,
                severity=Severity.MEDIUM,
            )]
        return []

    # ------------------------------------------------------------------
    # Format checking
    # ------------------------------------------------------------------

    @staticmethod
    def _check_format(
        fmt: str, value: str, path: str,
    ) -> List[SchemaViolation]:
        validators = {
            "email": r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            "uri": r"^https?://",
            "url": r"^https?://",
            "uuid": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "date": r"^\d{4}-\d{2}-\d{2}$",
            "date-time": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}",
            "ipv4": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            "ipv6": r"^[0-9a-fA-F:]+$",
        }

        pattern = validators.get(fmt)
        if pattern and not re.match(pattern, value, re.IGNORECASE):
            return [SchemaViolation(
                path=path,
                message=f"Invalid format '{fmt}': {value[:50]}",
                expected=f"format={fmt}",
                actual=value[:50],
            )]
        return []

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _to_findings(
        violations: List[SchemaViolation], target: Target,
    ) -> List[Finding]:
        if not violations:
            return []

        # Group by severity
        by_sev: Dict[Severity, List[SchemaViolation]] = {}
        for v in violations:
            by_sev.setdefault(v.severity, []).append(v)

        findings: List[Finding] = []
        for sev, items in by_sev.items():
            evidence = "\n".join(f"  {v.path}: {v.message}" for v in items[:20])
            findings.append(Finding(
                title=f"Response schema violations ({len(items)} issues)",
                description=(
                    f"API response from {target.url} has {len(items)} schema violations."
                ),
                severity=sev,
                target=target,
                evidence=evidence,
                remediation="Ensure API responses match their declared schema. Fix type mismatches, missing required fields, and constraint violations.",
                tags=["schema", "validation", "api"],
            ))

        return findings
