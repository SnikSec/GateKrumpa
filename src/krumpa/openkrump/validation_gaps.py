"""Server-side validation gaps — spec constraints vs. actual enforcement.

Phase 4 item #62.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.validation_gaps")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class ValidationTest:
    """A single validation test case."""
    field_name: str
    constraint: str      # minLength, maximum, pattern, enum, etc.
    spec_value: Any      # the spec's stated constraint value
    test_value: Any      # the value we're testing (should violate constraint)
    description: str = ""


@dataclass
class ValidationGap:
    """A discovered gap between spec constraints and server enforcement."""
    test: ValidationTest
    accepted: bool = False
    status_code: int = 0
    response: str = ""


class ValidationGapDetector:
    """Detect gaps between API spec constraints and server enforcement.

    Extracts parameter/schema constraints from the spec (minLength,
    maxLength, minimum, maximum, pattern, enum, required, format)
    and sends requests that violate each constraint. If the server
    accepts the invalid data, there's a validation gap.

    This is critical because:
    - Frontend-only validation is trivially bypassed
    - Spec documents the *intended* constraints; the server should enforce them
    - Gaps enable injection, overflow, and business logic attacks
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(
        self, target: Target, spec: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Run validation gap analysis."""
        findings: List[Finding] = []

        if not spec or not self._client:
            return findings

        # Extract constraint tests from spec
        tests = self._extract_tests(spec)
        if not tests:
            logger.info("No constraint tests extracted from spec")
            return findings

        logger.info("Generated %d validation tests from spec", len(tests))

        # Group tests by endpoint
        endpoint_tests = self._group_by_endpoint(tests, spec)

        for endpoint_path, methods in endpoint_tests.items():
            for method, test_cases in methods.items():
                for test in test_cases:
                    gap = await self._execute_test(
                        test, endpoint_path, method, target, spec,
                    )
                    if gap and gap.accepted:
                        findings.append(self._gap_to_finding(
                            gap, endpoint_path, method, target,
                        ))

        return findings

    # ----------------------------------------------------------
    # Constraint extraction
    # ----------------------------------------------------------

    def _extract_tests(self, spec: Dict[str, Any]) -> List[ValidationTest]:
        """Extract validation test cases from spec schemas."""
        tests: List[ValidationTest] = []
        paths = spec.get("paths", {})

        for _path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ("get", "post", "put", "patch", "delete"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                # Parameter constraints
                params = (
                    operation.get("parameters", [])
                    + path_item.get("parameters", [])
                )
                for param in params:
                    if not isinstance(param, dict):
                        continue
                    schema = param.get("schema", {})
                    name = param.get("name", "")
                    if not name or not isinstance(schema, dict):
                        continue
                    tests.extend(self._schema_to_tests(name, schema))

                # Request body constraints
                req_body = operation.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for _ct, media_type in content.items():
                        if isinstance(media_type, dict):
                            schema = media_type.get("schema", {})
                            if isinstance(schema, dict):
                                tests.extend(
                                    self._deep_schema_tests(schema, spec)
                                )

        return tests

    def _schema_to_tests(
        self, field_name: str, schema: Dict[str, Any],
    ) -> List[ValidationTest]:
        """Generate test cases for a single schema field."""
        tests: List[ValidationTest] = []
        field_type = schema.get("type", "string")

        # minLength violation
        min_len = schema.get("minLength")
        if min_len is not None and isinstance(min_len, int) and min_len > 0:
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="minLength",
                spec_value=min_len,
                test_value="",
                description=f"Empty string violates minLength={min_len}",
            ))

        # maxLength violation
        max_len = schema.get("maxLength")
        if max_len is not None and isinstance(max_len, int):
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="maxLength",
                spec_value=max_len,
                test_value="A" * (max_len + 100),
                description=f"String of length {max_len + 100} violates maxLength={max_len}",
            ))

        # minimum violation
        minimum = schema.get("minimum")
        if minimum is not None:
            exclusive = schema.get("exclusiveMinimum", False)
            test_val = minimum - 1 if not exclusive else minimum
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="minimum",
                spec_value=minimum,
                test_value=test_val,
                description=f"Value {test_val} violates minimum={minimum}",
            ))

        # maximum violation
        maximum = schema.get("maximum")
        if maximum is not None:
            exclusive = schema.get("exclusiveMaximum", False)
            test_val = maximum + 1 if not exclusive else maximum
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="maximum",
                spec_value=maximum,
                test_value=test_val,
                description=f"Value {test_val} violates maximum={maximum}",
            ))

        # pattern violation
        pattern = schema.get("pattern")
        if pattern:
            # Send a value that's unlikely to match the pattern
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="pattern",
                spec_value=pattern,
                test_value="!@#$%^&*()",
                description=f"Special chars unlikely to match pattern: {pattern}",
            ))

        # enum violation
        enum_vals = schema.get("enum")
        if enum_vals and isinstance(enum_vals, list):
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="enum",
                spec_value=enum_vals,
                test_value="__INVALID_ENUM_VALUE__",
                description=f"Value not in enum: {enum_vals[:5]}",
            ))

        # format violation
        fmt = schema.get("format")
        if fmt:
            invalid = self._invalid_for_format(fmt)
            if invalid is not None:
                tests.append(ValidationTest(
                    field_name=field_name,
                    constraint="format",
                    spec_value=fmt,
                    test_value=invalid,
                    description=f"Invalid value for format={fmt}",
                ))

        # Type violation (send string for integer, etc.)
        if field_type == "integer":
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="type",
                spec_value="integer",
                test_value="not_a_number",
                description="String value for integer field",
            ))
        elif field_type == "boolean":
            tests.append(ValidationTest(
                field_name=field_name,
                constraint="type",
                spec_value="boolean",
                test_value="maybe",
                description="Non-boolean string for boolean field",
            ))

        return tests

    def _deep_schema_tests(
        self, schema: Dict[str, Any], spec: Dict[str, Any],
    ) -> List[ValidationTest]:
        """Recursively extract tests from a schema (incl. properties)."""
        tests: List[ValidationTest] = []

        # Resolve $ref if present
        schema = self._resolve_ref(schema, spec)

        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if isinstance(prop_schema, dict):
                resolved = self._resolve_ref(prop_schema, spec)
                tests.extend(self._schema_to_tests(prop_name, resolved))

        # Required field omission
        required_fields = schema.get("required", [])
        for req_field in required_fields:
            tests.append(ValidationTest(
                field_name=req_field,
                constraint="required",
                spec_value=True,
                test_value=None,  # Will be omitted from request
                description=f"Required field '{req_field}' omitted",
            ))

        return tests

    @staticmethod
    def _resolve_ref(
        schema: Dict[str, Any], spec: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve a $ref pointer (one level deep)."""
        ref = schema.get("$ref")
        if not ref or not isinstance(ref, str):
            return schema

        parts = ref.lstrip("#/").split("/")
        resolved = spec
        for part in parts:
            if isinstance(resolved, dict):
                resolved = resolved.get(part, {})
            else:
                return schema
        return resolved if isinstance(resolved, dict) else schema

    @staticmethod
    def _invalid_for_format(fmt: str) -> Optional[str]:
        """Return an invalid value for a given format."""
        invalids: Dict[str, str] = {
            "email": "not-an-email",
            "uri": "not a uri at all",
            "url": "not a url at all",
            "uuid": "not-a-uuid",
            "date": "not-a-date",
            "date-time": "not-a-datetime",
            "ipv4": "999.999.999.999",
            "ipv6": "not:an:ipv6",
            "hostname": "invalid hostname!@#",
        }
        return invalids.get(fmt)

    # ----------------------------------------------------------
    # Test grouping
    # ----------------------------------------------------------

    def _group_by_endpoint(
        self,
        tests: List[ValidationTest],
        spec: Dict[str, Any],
    ) -> Dict[str, Dict[str, List[ValidationTest]]]:
        """Group tests by endpoint path and method."""
        grouped: Dict[str, Dict[str, List[ValidationTest]]] = {}
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                # Find relevant tests for this endpoint's fields
                endpoint_fields = set()
                for p in operation.get("parameters", []) + path_item.get("parameters", []):
                    if isinstance(p, dict):
                        endpoint_fields.add(p.get("name", ""))

                # Request body fields
                req_body = operation.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for _ct, mt in content.items():
                        if isinstance(mt, dict):
                            schema = mt.get("schema", {})
                            if isinstance(schema, dict):
                                schema = self._resolve_ref(schema, spec)
                                endpoint_fields.update(
                                    schema.get("properties", {}).keys()
                                )
                                endpoint_fields.update(
                                    schema.get("required", [])
                                )

                matching = [t for t in tests if t.field_name in endpoint_fields]
                if matching:
                    grouped.setdefault(path, {})[method] = matching

        return grouped

    # ----------------------------------------------------------
    # Test execution
    # ----------------------------------------------------------

    async def _execute_test(
        self,
        test: ValidationTest,
        path: str,
        method: str,
        target: Target,
        spec: Dict[str, Any],
    ) -> Optional[ValidationGap]:
        """Execute a single validation test."""
        if not self._client:
            return None

        url = urljoin(target.url.rstrip("/") + "/", path.lstrip("/"))

        # Build request with the test value
        try:
            if method.upper() in ("POST", "PUT", "PATCH"):
                body: Dict[str, Any] = {}

                if test.constraint == "required" and test.test_value is None:
                    # Omit the required field entirely
                    body = {"_dummy": "value"}
                else:
                    body = {test.field_name: test.test_value}

                resp = await self._client.request(
                    method.upper(), url, json_body=body,
                )
            else:
                # Query parameter
                sep = "&" if "?" in url else "?"
                if test.constraint == "required" and test.test_value is None:
                    param_url = url  # Omit the param
                else:
                    val = str(test.test_value) if test.test_value is not None else ""
                    param_url = f"{url}{sep}{test.field_name}={val}"

                resp = await self._client.request(method.upper(), param_url)

            # If server accepted the invalid input (2xx), it's a gap
            accepted = 200 <= resp.status_code < 300

            return ValidationGap(
                test=test,
                accepted=accepted,
                status_code=resp.status_code,
                response=resp.text[:500],
            )

        except Exception as exc:
            logger.debug("Test failed for %s: %s", test.field_name, exc)
            return None

    # ----------------------------------------------------------
    # Finding generation
    # ----------------------------------------------------------

    def _gap_to_finding(
        self,
        gap: ValidationGap,
        path: str,
        method: str,
        target: Target,
    ) -> Finding:
        """Convert a validation gap to a Finding."""
        test = gap.test
        severity = self._gap_severity(test)

        return Finding(
            title=f"Validation gap: {test.constraint} not enforced on '{test.field_name}'",
            description=(
                f"The API spec declares {test.constraint}={test.spec_value} for "
                f"field '{test.field_name}' on {method.upper()} {path}, "
                f"but the server accepted a request violating this constraint. "
                f"This means the spec is not enforced server-side."
            ),
            severity=severity,
            target=target,
            evidence=(
                f"Endpoint: {method.upper()} {path}\n"
                f"Constraint: {test.constraint}={test.spec_value}\n"
                f"Test value: {str(test.test_value)[:200]}\n"
                f"Server response: {gap.status_code}\n"
                f"Description: {test.description}"
            ),
            remediation=(
                "Implement server-side validation matching the API spec constraints. "
                "Never rely on client-side validation alone. Use a validation "
                "library that can consume OpenAPI schemas directly."
            ),
            cwe=20,
            tags=["validation-gap", "spec-enforcement", test.constraint, "openkrump"],
        )

    @staticmethod
    def _gap_severity(test: ValidationTest) -> Severity:
        """Determine severity based on the type of validation gap."""
        high_risk = {"pattern", "enum", "type", "format"}
        if test.constraint in high_risk:
            return Severity.MEDIUM

        if test.constraint in ("required",):
            return Severity.LOW

        if test.constraint in ("minimum", "maximum", "minLength", "maxLength"):
            return Severity.LOW

        return Severity.LOW
