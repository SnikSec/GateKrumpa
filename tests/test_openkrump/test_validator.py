"""Tests for krumpa.openkrump.validator — schema validator."""

from krumpa.core import Severity, Target
from krumpa.openkrump.parser import ParsedEndpoint
from krumpa.openkrump.validator import SchemaValidator, ValidationIssue


def _endpoint(**kw) -> ParsedEndpoint:
    defaults = dict(path="/test", method="GET")
    defaults.update(kw)
    return ParsedEndpoint(**defaults)


# ------------------------------------------------------------------
# Response validation
# ------------------------------------------------------------------

class TestValidateResponse:
    def test_valid_object(self):
        ep = _endpoint(response_schemas={
            "200": {"type": "object", "properties": {"name": {"type": "string"}}},
        })
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, {"name": "Alice"})
        assert issues == []

    def test_type_mismatch_at_root(self):
        ep = _endpoint(response_schemas={"200": {"type": "object"}})
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, "not an object")
        assert len(issues) == 1
        assert issues[0].issue_type == "type_mismatch"

    def test_missing_required_field(self):
        ep = _endpoint(response_schemas={
            "200": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer"}},
            },
        })
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, {})
        assert any(i.issue_type == "missing_field" for i in issues)

    def test_nested_type_mismatch(self):
        ep = _endpoint(response_schemas={
            "200": {
                "type": "object",
                "properties": {"count": {"type": "integer"}},
            },
        })
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, {"count": "not_int"})
        assert any(i.issue_type == "type_mismatch" for i in issues)

    def test_array_validation(self):
        ep = _endpoint(response_schemas={
            "200": {
                "type": "array",
                "items": {"type": "object", "properties": {"id": {"type": "integer"}}},
            },
        })
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, [{"id": 1}])
        assert issues == []

    def test_array_type_mismatch(self):
        ep = _endpoint(response_schemas={"200": {"type": "array"}})
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, "not an array")
        assert issues[0].issue_type == "type_mismatch"

    def test_undocumented_status_code(self):
        ep = _endpoint(response_schemas={"200": {"type": "object"}})
        v = SchemaValidator()
        issues = v.validate_response(ep, 404, {})
        assert issues[0].issue_type == "undocumented_status"

    def test_no_schema_at_all(self):
        ep = _endpoint()  # no response_schemas
        v = SchemaValidator()
        issues = v.validate_response(ep, 200, {"anything": True})
        assert issues[0].issue_type == "undocumented_status"


class TestStrictMode:
    def test_flags_extra_fields(self):
        ep = _endpoint(response_schemas={
            "200": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
            },
        })
        v = SchemaValidator(strict=True)
        issues = v.validate_response(ep, 200, {"name": "A", "secret": "oops"})
        assert any(i.issue_type == "extra_field" for i in issues)

    def test_no_extra_flags_non_strict(self):
        ep = _endpoint(response_schemas={
            "200": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
            },
        })
        v = SchemaValidator(strict=False)
        issues = v.validate_response(ep, 200, {"name": "A", "secret": "oops"})
        assert not any(i.issue_type == "extra_field" for i in issues)


# ------------------------------------------------------------------
# Security checks
# ------------------------------------------------------------------

class TestSecurityChecks:
    def test_flags_no_security(self):
        ep = _endpoint(security=[])
        v = SchemaValidator()
        issues = v.check_security(ep)
        assert len(issues) == 1
        assert issues[0].issue_type == "no_security"

    def test_passes_with_security(self):
        ep = _endpoint(security=[{"bearerAuth": []}])
        v = SchemaValidator()
        issues = v.check_security(ep)
        assert issues == []


class TestDeprecatedCheck:
    def test_flags_deprecated(self):
        ep = _endpoint(deprecated=True)
        issues = SchemaValidator().check_deprecated(ep)
        assert len(issues) == 1
        assert issues[0].issue_type == "deprecated"

    def test_not_deprecated(self):
        ep = _endpoint(deprecated=False)
        issues = SchemaValidator().check_deprecated(ep)
        assert issues == []


# ------------------------------------------------------------------
# Issue → Finding conversion
# ------------------------------------------------------------------

class TestIssuesToFindings:
    def test_converts_issues(self):
        ep = _endpoint()
        issue = ValidationIssue(
            endpoint=ep, issue_type="type_mismatch",
            detail="Expected string got int", severity=Severity.LOW,
        )
        v = SchemaValidator()
        findings = v.issues_to_findings([issue], Target(url="https://example.com"))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "type_mismatch" in findings[0].tags

    def test_empty_issues(self):
        v = SchemaValidator()
        assert v.issues_to_findings([], Target(url="https://x.com")) == []
