"""Tests for reporting — to_json(), to_sarif(), to_markdown(), _redact()."""

from __future__ import annotations

import json

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.reporting import to_json, to_sarif, to_markdown, _redact


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _ctx_with_findings(*findings: Finding) -> ScanContext:
    ctx = ScanContext()
    for f in findings:
        ctx.add_finding(f)
    return ctx


def _sample_finding(**overrides) -> Finding:
    defaults = dict(
        title="SQL Injection in /login",
        description="Tautology-based SQLi detected.",
        severity=Severity.HIGH,
        module="grotassault",
        target=Target(url="https://api.example.com/login"),
        evidence="' OR 1=1 --",
        remediation="Use parameterised queries.",
        cwe=89,
        tags=["injection", "sqli"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ------------------------------------------------------------------
# _redact()
# ------------------------------------------------------------------

class TestRedact:

    def test_redacts_password_equals(self):
        text = "Found password=hunter2 in response"
        assert "hunter2" not in _redact(text)
        assert "***REDACTED***" in _redact(text)

    def test_redacts_token_colon(self):
        text = "token: eyJhbGciOiJIUzI1NiJ9"
        result = _redact(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "***REDACTED***" in result

    def test_redacts_bearer(self):
        text = "authorization=Bearer_abc123"
        result = _redact(text)
        assert "Bearer_abc123" not in result

    def test_case_insensitive(self):
        text = "PASSWORD=secret123"
        result = _redact(text)
        assert "secret123" not in result

    def test_leaves_non_sensitive_text(self):
        text = "status=200 message=OK"
        assert _redact(text) == text

    def test_redacts_api_key(self):
        text = "api_key=AKIAIOSFODNN7EXAMPLE"
        result = _redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_multiple_sensitive_values(self):
        text = "password=a secret=b token=c"
        result = _redact(text)
        assert "a" not in result.split("password")[1].split(" ")[0]  # rough check
        assert "***REDACTED***" in result


# ------------------------------------------------------------------
# to_json()
# ------------------------------------------------------------------

class TestToJson:

    def test_empty_findings(self):
        ctx = ScanContext()
        raw = to_json(ctx)
        data = json.loads(raw)
        assert data["total_findings"] == 0
        assert data["findings"] == []

    def test_single_finding(self):
        ctx = _ctx_with_findings(_sample_finding())
        data = json.loads(to_json(ctx))
        assert data["total_findings"] == 1
        f = data["findings"][0]
        assert f["title"] == "SQL Injection in /login"
        assert f["severity"] == "high"
        assert f["module"] == "grotassault"
        assert f["target"] == "https://api.example.com/login"

    def test_multiple_findings(self):
        f1 = _sample_finding(title="A", severity=Severity.CRITICAL)
        f2 = _sample_finding(title="B", severity=Severity.LOW)
        ctx = _ctx_with_findings(f1, f2)
        data = json.loads(to_json(ctx))
        assert data["total_findings"] == 2
        assert data["findings_by_severity"]["critical"] == 1
        assert data["findings_by_severity"]["low"] == 1

    def test_valid_json(self):
        ctx = _ctx_with_findings(_sample_finding())
        raw = to_json(ctx)
        json.loads(raw)  # should not raise

    def test_includes_scan_id(self):
        ctx = ScanContext()
        data = json.loads(to_json(ctx))
        assert "scan_id" in data
        assert len(data["scan_id"]) == 16

    def test_custom_indent(self):
        ctx = ScanContext()
        raw = to_json(ctx, indent=4)
        # 4-space indent means lines should start with "    "
        assert "    " in raw


# ------------------------------------------------------------------
# to_sarif()
# ------------------------------------------------------------------

class TestToSarif:

    def test_schema_present(self):
        ctx = ScanContext()
        sarif = to_sarif(ctx)
        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"

    def test_tool_metadata(self):
        sarif = to_sarif(ScanContext())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "GateKrumpa"
        assert driver["version"] == "0.2.0"
        assert "GateKrumpa" in driver["informationUri"]

    def test_empty_findings(self):
        sarif = to_sarif(ScanContext())
        assert sarif["runs"][0]["results"] == []

    def test_single_finding(self):
        ctx = _ctx_with_findings(_sample_finding())
        sarif = to_sarif(ctx)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        r = results[0]
        assert r["message"]["text"] == "SQL Injection in /login"
        assert r["level"] == "error"  # HIGH maps to error

    def test_severity_mapping(self):
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        for sev, expected in mapping.items():
            ctx = _ctx_with_findings(_sample_finding(severity=sev))
            sarif = to_sarif(ctx)
            assert sarif["runs"][0]["results"][0]["level"] == expected

    def test_location_from_target(self):
        ctx = _ctx_with_findings(_sample_finding())
        sarif = to_sarif(ctx)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "https://api.example.com/login"

    def test_location_without_target(self):
        f = _sample_finding(target=None)
        ctx = _ctx_with_findings(f)
        sarif = to_sarif(ctx)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "unknown"

    def test_multiple_findings(self):
        f1 = _sample_finding(title="A")
        f2 = _sample_finding(title="B")
        ctx = _ctx_with_findings(f1, f2)
        sarif = to_sarif(ctx)
        assert len(sarif["runs"][0]["results"]) == 2


# ------------------------------------------------------------------
# to_markdown()
# ------------------------------------------------------------------

class TestToMarkdown:

    def test_contains_header(self):
        ctx = ScanContext()
        md = to_markdown(ctx)
        assert "# GateKrumpa Scan Report" in md

    def test_contains_scan_id(self):
        ctx = ScanContext()
        md = to_markdown(ctx)
        assert ctx.scan_id in md

    def test_empty_findings(self):
        ctx = ScanContext()
        md = to_markdown(ctx)
        assert "Total findings:** 0" in md

    def test_single_finding_section(self):
        ctx = _ctx_with_findings(_sample_finding())
        md = to_markdown(ctx)
        assert "## [HIGH] SQL Injection in /login" in md
        assert "grotassault" in md
        assert "api.example.com/login" in md

    def test_severity_counts(self):
        f1 = _sample_finding(severity=Severity.CRITICAL, title="A")
        f2 = _sample_finding(severity=Severity.CRITICAL, title="B")
        f3 = _sample_finding(severity=Severity.LOW, title="C")
        md = to_markdown(_ctx_with_findings(f1, f2, f3))
        assert "**CRITICAL**: 2" in md
        assert "**LOW**: 1" in md

    def test_evidence_included(self):
        f = _sample_finding(evidence="token=SENSITIVE123")
        md = to_markdown(_ctx_with_findings(f))
        assert "Evidence" in md
        # Evidence should be redacted
        assert "SENSITIVE123" not in md

    def test_remediation_included(self):
        ctx = _ctx_with_findings(_sample_finding())
        md = to_markdown(ctx)
        assert "parameterised queries" in md

    def test_evidence_redaction_in_markdown(self):
        f = _sample_finding(evidence="password=secret123")
        md = to_markdown(_ctx_with_findings(f))
        assert "secret123" not in md
        assert "***REDACTED***" in md

    def test_target_count(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com"))
        ctx.add_target(Target(url="https://b.com"))
        md = to_markdown(ctx)
        assert "Targets scanned:** 2" in md

    def test_no_target_on_finding(self):
        f = _sample_finding(target=None)
        md = to_markdown(_ctx_with_findings(f))
        # Should not crash, and should not contain "Target:" for this finding
        assert "# GateKrumpa Scan Report" in md
