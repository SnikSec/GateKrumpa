"""
OpenKrump — Parameter constraint testing.

Generate negative test cases from OpenAPI spec constraints:
- min/max, minLength/maxLength, pattern (regex)
- enum violations, required field omission
- type confusion (string where int expected, etc.)
- format violations (email, uuid, date-time)

Each violation is sent as a live request to verify server-side enforcement.
"""

from __future__ import annotations

import logging
import random
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin
from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.param_constraint_tester")


@dataclass
class ConstraintViolation(HttpClientMixin):
    """A single negative test case generated from a spec constraint."""
    param_name: str
    constraint_type: str  # min, max, minLength, maxLength, pattern, enum, required, type, format
    spec_value: Any  # the expected constraint value
    test_value: Any  # the violating value we'll send
    description: str


@dataclass
class ConstraintTestResult(HttpClientMixin):
    """Result of sending a single constraint violation."""
    violation: ConstraintViolation
    accepted: bool  # True = server accepted invalid value (bad)
    status_code: int
    evidence: str


class ParamConstraintTester(HttpClientMixin):
    """
    Generate negative tests from OpenAPI parameter constraints,
    send them as live requests, and flag missing server-side validation.

    For each parameter with constraints (minimum, maximum, minLength,
    maxLength, pattern, enum, required, type, format), generates one
    or more violating values and fires them at the endpoint.

    A finding is raised when the server returns 2xx for invalid input,
    indicating missing or incomplete input validation.
    """

    ACCEPTED_RANGE = range(200, 300)

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def test_endpoints(
        self,
        endpoints: List[ParsedEndpoint],
        base_url: str,
    ) -> List[Finding]:
        """
        Test all endpoints' parameters for missing constraint enforcement.
        """
        findings: List[Finding] = []

        for ep in endpoints:
            ep_findings = await self._test_endpoint(ep, base_url)
            findings.extend(ep_findings)

        return findings

    async def _test_endpoint(
        self, ep: ParsedEndpoint, base_url: str,
    ) -> List[Finding]:
        """Test a single endpoint's parameter constraints."""
        findings: List[Finding] = []
        url = base_url.rstrip("/") + "/" + ep.path.lstrip("/")
        target = Target(url=url, method=ep.method)

        # Test query/header/path parameters
        for param in ep.parameters:
            schema = param.get("schema", {})
            name = param.get("name", "")
            location = param.get("in", "query")
            required = param.get("required", False)

            violations = self._generate_violations(name, schema, required)
            for violation in violations:
                result = await self._send_violation(ep, url, violation, location)
                if result and result.accepted:
                    findings.append(self._build_finding(target, ep, result))

        # Test request body schema constraints
        if ep.request_body_schema:
            body_violations = self._generate_body_violations(ep.request_body_schema)
            for violation in body_violations:
                result = await self._send_body_violation(ep, url, violation)
                if result and result.accepted:
                    findings.append(self._build_finding(target, ep, result))

        return findings

    # ------------------------------------------------------------------
    # Violation generators
    # ------------------------------------------------------------------

    def _generate_violations(
        self, name: str, schema: Dict[str, Any], required: bool,
    ) -> List[ConstraintViolation]:
        """Generate violating values from a parameter's schema."""
        violations: List[ConstraintViolation] = []
        param_type = schema.get("type", "string")

        # minimum / maximum (numeric)
        if "minimum" in schema:
            val = schema["minimum"] - 1
            if schema.get("exclusiveMinimum"):
                val = schema["minimum"]
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="minimum",
                spec_value=schema["minimum"], test_value=val,
                description=f"value {val} below minimum {schema['minimum']}",
            ))

        if "maximum" in schema:
            val = schema["maximum"] + 1
            if schema.get("exclusiveMaximum"):
                val = schema["maximum"]
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="maximum",
                spec_value=schema["maximum"], test_value=val,
                description=f"value {val} above maximum {schema['maximum']}",
            ))

        # minLength / maxLength (string)
        if "minLength" in schema and schema["minLength"] > 0:
            short = "x" * max(0, schema["minLength"] - 1)
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="minLength",
                spec_value=schema["minLength"], test_value=short,
                description=f"string length {len(short)} below minLength {schema['minLength']}",
            ))

        if "maxLength" in schema:
            long = "x" * (schema["maxLength"] + 10)
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="maxLength",
                spec_value=schema["maxLength"], test_value=long,
                description=f"string length {len(long)} above maxLength {schema['maxLength']}",
            ))

        # pattern (regex)
        if "pattern" in schema:
            # Generate a string that doesn't match the pattern
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="pattern",
                spec_value=schema["pattern"], test_value="!!!INVALID_PATTERN!!!",
                description=f"value does not match pattern /{schema['pattern']}/",
            ))

        # enum
        if "enum" in schema:
            enum_vals = schema["enum"]
            invalid = "INVALID_ENUM_VALUE_" + "".join(random.choices(string.ascii_uppercase, k=4))
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="enum",
                spec_value=enum_vals, test_value=invalid,
                description=f"value '{invalid}' not in enum {enum_vals}",
            ))

        # type confusion
        type_confusions = self._type_confusion_values(param_type)
        for confused_type, confused_value in type_confusions:
            violations.append(ConstraintViolation(
                param_name=name, constraint_type="type",
                spec_value=param_type, test_value=confused_value,
                description=f"sent {confused_type} where {param_type} expected",
            ))

        # format
        if "format" in schema:
            fmt = schema["format"]
            invalid_val = self._invalid_format_value(fmt)
            if invalid_val is not None:
                violations.append(ConstraintViolation(
                    param_name=name, constraint_type="format",
                    spec_value=fmt, test_value=invalid_val,
                    description=f"invalid {fmt} format",
                ))

        # required (test omission) — handled at endpoint level, not here
        return violations

    def _generate_body_violations(
        self, body_schema: Dict[str, Any],
    ) -> List[ConstraintViolation]:
        """Generate violations from request body schema."""
        violations: List[ConstraintViolation] = []
        properties = body_schema.get("properties", {})
        required_fields = set(body_schema.get("required", []))

        for prop_name, prop_schema in properties.items():
            violations.extend(
                self._generate_violations(prop_name, prop_schema, prop_name in required_fields)
            )

        # Test omitting required fields
        for req_field in required_fields:
            violations.append(ConstraintViolation(
                param_name=req_field, constraint_type="required",
                spec_value=True, test_value="<OMITTED>",
                description=f"required field '{req_field}' omitted from request body",
            ))

        return violations

    @staticmethod
    def _type_confusion_values(expected_type: str) -> List[Tuple[str, Any]]:
        """Generate values of incorrect types."""
        confusions: Dict[str, List[Tuple[str, Any]]] = {
            "integer": [("string", "not_a_number"), ("boolean", True), ("float", 1.5)],
            "number": [("string", "not_a_number"), ("boolean", True)],
            "string": [("integer", 12345), ("boolean", True), ("array", [1, 2])],
            "boolean": [("string", "not_bool"), ("integer", 42)],
            "array": [("string", "not_array"), ("integer", 42)],
            "object": [("string", "not_object"), ("array", [1, 2])],
        }
        return confusions.get(expected_type, [])

    @staticmethod
    def _invalid_format_value(fmt: str) -> Optional[str]:
        """Return an invalid value for a known format."""
        invalid_formats: Dict[str, str] = {
            "email": "not-an-email",
            "uuid": "not-a-uuid",
            "date-time": "not-a-datetime",
            "date": "not-a-date",
            "uri": "not a valid uri %%%",
            "hostname": "invalid..hostname...!!",
            "ipv4": "999.999.999.999",
            "ipv6": "not-ipv6",
            "int32": "9999999999999",
            "int64": "not_int",
            "float": "not_float",
            "double": "not_double",
            "password": "",  # empty password
            "byte": "!!not-base64!!",
            "binary": "",  # empty binary
        }
        return invalid_formats.get(fmt)

    # ------------------------------------------------------------------
    # Request senders
    # ------------------------------------------------------------------

    async def _send_violation(
        self,
        ep: ParsedEndpoint,
        url: str,
        violation: ConstraintViolation,
        location: str,
    ) -> Optional[ConstraintTestResult]:
        """Send a single parameter violation."""
        if not self._client:
            return None

        method = ep.method
        headers: Dict[str, str] = {"Accept": "application/json"}
        test_url = url

        if location == "query":
            sep = "&" if "?" in test_url else "?"
            test_url = f"{test_url}{sep}{violation.param_name}={violation.test_value}"
        elif location == "header":
            headers[violation.param_name] = str(violation.test_value)
        elif location == "path":
            test_url = test_url.replace(f"{{{violation.param_name}}}", str(violation.test_value))

        try:
            resp = await self._client.request(method, test_url, headers=headers)
            accepted = resp.status_code in self.ACCEPTED_RANGE
            return ConstraintTestResult(
                violation=violation,
                accepted=accepted,
                status_code=resp.status_code,
                evidence=f"status={resp.status_code}, {violation.description}",
            )
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Constraint test error: %s", exc)
            return None

    async def _send_body_violation(
        self,
        ep: ParsedEndpoint,
        url: str,
        violation: ConstraintViolation,
    ) -> Optional[ConstraintTestResult]:
        """Send a request body violation."""
        if not self._client:
            return None

        import json
        method = ep.method
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Build a body with the violating value
        if violation.constraint_type == "required":
            # Omit the field — send empty body
            body = json.dumps({})
        else:
            body = json.dumps({violation.param_name: violation.test_value})

        try:
            resp = await self._client.request(method, url, headers=headers, body=body)
            accepted = resp.status_code in self.ACCEPTED_RANGE
            return ConstraintTestResult(
                violation=violation,
                accepted=accepted,
                status_code=resp.status_code,
                evidence=f"status={resp.status_code}, body={body[:200]}, {violation.description}",
            )
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Body constraint test error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding(
        target: Target,
        ep: ParsedEndpoint,
        result: ConstraintTestResult,
    ) -> Finding:
        """Build a Finding for a missing constraint."""
        v = result.violation
        severity = Severity.MEDIUM
        if v.constraint_type in ("type", "required"):
            severity = Severity.HIGH
        if v.constraint_type in ("minimum", "maximum", "minLength", "maxLength"):
            severity = Severity.LOW

        return Finding(
            title=(
                f"Missing {v.constraint_type} validation on "
                f"'{v.param_name}' ({ep.method.upper()} {ep.path})"
            ),
            description=(
                f"Parameter '{v.param_name}' has a {v.constraint_type} constraint "
                f"(spec: {v.spec_value}) but the server accepted the violating value "
                f"'{v.test_value}' with status {result.status_code}."
            ),
            severity=severity,
            target=target,
            evidence=result.evidence,
            remediation=(
                f"Implement server-side validation for the {v.constraint_type} constraint "
                f"on parameter '{v.param_name}'. Return 400 for invalid input."
            ),
            cwe=20,
            tags=["param-constraint", v.constraint_type, "api", "openkrump"],
        )
