"""Tests for krumpa.waaaghgate.reporter — pipeline report generator."""

import json
import pytest
from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.waaaghgate.gate import GatePolicy, GateResult
from krumpa.waaaghgate.reporter import PipelineReporter, ReportFormat


def _finding(sev: Severity = Severity.HIGH, cwe: int = 79) -> Finding:
    return Finding(
        title="Test finding",
        severity=sev,
        target=Target(url="https://example.com/api"),
        cwe=cwe,
        tags=["test"],
    )


class TestJsonReport:
    def test_valid_json(self):
        r = PipelineReporter(formats=[ReportFormat.JSON])
        reports = r.generate([_finding()])
        doc = json.loads(reports[ReportFormat.JSON])
        assert doc["tool"] == "GateKrumpa"
        assert doc["total"] == 1

    def test_includes_gate_result(self):
        r = PipelineReporter(formats=[ReportFormat.JSON])
        gate = GatePolicy().evaluate([_finding(Severity.CRITICAL)])
        reports = r.generate([_finding(Severity.CRITICAL)], gate_result=gate)
        doc = json.loads(reports[ReportFormat.JSON])
        assert "gate" in doc
        assert doc["gate"]["passed"] is False

    def test_includes_scan_context(self):
        r = PipelineReporter(formats=[ReportFormat.JSON])
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        reports = r.generate([], ctx=ctx)
        doc = json.loads(reports[ReportFormat.JSON])
        assert "scan" in doc

    def test_empty_findings(self):
        r = PipelineReporter(formats=[ReportFormat.JSON])
        reports = r.generate([])
        doc = json.loads(reports[ReportFormat.JSON])
        assert doc["total"] == 0
        assert doc["findings"] == []


class TestSarifReport:
    def test_valid_sarif_structure(self):
        r = PipelineReporter(formats=[ReportFormat.SARIF])
        reports = r.generate([_finding()])
        doc = json.loads(reports[ReportFormat.SARIF])
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["tool"]["driver"]["name"] == "GateKrumpa"

    def test_findings_as_results(self):
        r = PipelineReporter(formats=[ReportFormat.SARIF])
        reports = r.generate([_finding(cwe=89)])
        doc = json.loads(reports[ReportFormat.SARIF])
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-89"

    def test_severity_mapping(self):
        r = PipelineReporter(formats=[ReportFormat.SARIF])
        reports = r.generate([_finding(Severity.CRITICAL)])
        doc = json.loads(reports[ReportFormat.SARIF])
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_low_severity_is_note(self):
        r = PipelineReporter(formats=[ReportFormat.SARIF])
        reports = r.generate([_finding(Severity.LOW)])
        doc = json.loads(reports[ReportFormat.SARIF])
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_location_from_target(self):
        r = PipelineReporter(formats=[ReportFormat.SARIF])
        reports = r.generate([_finding()])
        doc = json.loads(reports[ReportFormat.SARIF])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert "https://example.com/api" in loc["physicalLocation"]["artifactLocation"]["uri"]


class TestMarkdownReport:
    def test_contains_header(self):
        r = PipelineReporter(formats=[ReportFormat.MARKDOWN])
        reports = r.generate([_finding()])
        md = reports[ReportFormat.MARKDOWN]
        assert "# GateKrumpa Scan Report" in md

    def test_contains_table_row(self):
        r = PipelineReporter(formats=[ReportFormat.MARKDOWN])
        reports = r.generate([_finding()])
        md = reports[ReportFormat.MARKDOWN]
        assert "Test finding" in md
        assert "CWE-79" in md

    def test_gate_pass_status(self):
        r = PipelineReporter(formats=[ReportFormat.MARKDOWN])
        gate = GateResult(passed=True, summary="Gate PASSED")
        reports = r.generate([], gate_result=gate)
        md = reports[ReportFormat.MARKDOWN]
        assert "PASSED" in md

    def test_gate_fail_status(self):
        r = PipelineReporter(formats=[ReportFormat.MARKDOWN])
        gate = GatePolicy().evaluate([_finding(Severity.CRITICAL)])
        reports = r.generate([_finding(Severity.CRITICAL)], gate_result=gate)
        md = reports[ReportFormat.MARKDOWN]
        assert "FAILED" in md

    def test_empty_findings(self):
        r = PipelineReporter(formats=[ReportFormat.MARKDOWN])
        reports = r.generate([])
        assert "0" in reports[ReportFormat.MARKDOWN]


class TestMultiFormat:
    def test_generates_all_requested_formats(self):
        r = PipelineReporter(formats=[ReportFormat.JSON, ReportFormat.SARIF, ReportFormat.MARKDOWN])
        reports = r.generate([_finding()])
        assert ReportFormat.JSON in reports
        assert ReportFormat.SARIF in reports
        assert ReportFormat.MARKDOWN in reports
