"""Tests for enhanced reporting — HTML, JUnit, severity sorting."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.reporting import (
    to_html,
    to_json,
    to_junit,
    to_markdown,
    to_sarif,
    _sorted_findings,
    _SEVERITY_ORDER,
)


def _make_ctx(*severities: Severity) -> ScanContext:
    """Build a ScanContext with findings at the given severities."""
    ctx = ScanContext()
    target = Target(url="https://api.example.com/test")
    ctx.add_target(target)
    for i, sev in enumerate(severities):
        ctx.add_finding(Finding(
            title=f"Finding {i}",
            severity=sev,
            module="TestModule",
            target=target,
            evidence=f"Evidence {i}",
            remediation=f"Fix {i}",
            cwe=79 + i,
        ))
    return ctx


# ------------------------------------------------------------------
# Severity sorting
# ------------------------------------------------------------------

class TestSeveritySorting:

    def test_sorted_findings_order(self):
        findings = [
            Finding(title="low", severity=Severity.LOW),
            Finding(title="crit", severity=Severity.CRITICAL),
            Finding(title="med", severity=Severity.MEDIUM),
            Finding(title="high", severity=Severity.HIGH),
            Finding(title="info", severity=Severity.INFO),
        ]
        result = _sorted_findings(findings)
        assert [f.severity for f in result] == [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFO,
        ]

    def test_sorted_empty(self):
        assert _sorted_findings([]) == []

    def test_severity_order_complete(self):
        """All Severity enum values have an order entry."""
        for sev in Severity:
            assert sev in _SEVERITY_ORDER

    def test_json_findings_sorted(self):
        import json
        ctx = _make_ctx(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM)
        data = json.loads(to_json(ctx))
        sevs = [f["severity"] for f in data["findings"]]
        assert sevs == ["critical", "medium", "low"]

    def test_sarif_results_sorted(self):
        ctx = _make_ctx(Severity.INFO, Severity.HIGH)
        sarif = to_sarif(ctx)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "note"]

    def test_markdown_findings_sorted(self):
        ctx = _make_ctx(Severity.LOW, Severity.CRITICAL)
        md = to_markdown(ctx)
        # CRITICAL should appear before LOW in the output
        crit_pos = md.index("[CRITICAL]")
        low_pos = md.index("[LOW]")
        assert crit_pos < low_pos


# ------------------------------------------------------------------
# HTML report
# ------------------------------------------------------------------

class TestHtmlReport:

    def test_contains_doctype(self):
        ctx = _make_ctx(Severity.HIGH)
        html = to_html(ctx)
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_scan_id(self):
        ctx = _make_ctx()
        html = to_html(ctx)
        assert ctx.scan_id in html

    def test_contains_severity_badges(self):
        ctx = _make_ctx(Severity.CRITICAL, Severity.LOW)
        html = to_html(ctx)
        assert "critical" in html.lower()
        assert "low" in html.lower()

    def test_contains_finding_titles(self):
        ctx = _make_ctx(Severity.MEDIUM)
        html = to_html(ctx)
        assert "Finding 0" in html

    def test_findings_sorted_in_html(self):
        ctx = _make_ctx(Severity.LOW, Severity.HIGH, Severity.CRITICAL)
        html = to_html(ctx)
        crit_pos = html.index("Finding 2")  # CRITICAL
        high_pos = html.index("Finding 1")  # HIGH
        low_pos = html.index("Finding 0")   # LOW
        assert crit_pos < high_pos < low_pos

    def test_empty_findings(self):
        ctx = _make_ctx()
        html = to_html(ctx)
        assert "Total findings:</strong> 0" in html

    def test_target_count(self):
        ctx = _make_ctx(Severity.INFO)
        html = to_html(ctx)
        assert "Targets:</strong> 1" in html

    def test_cwe_in_html(self):
        ctx = _make_ctx(Severity.HIGH)
        html = to_html(ctx)
        assert "CWE-79" in html

    def test_html_escapes_xss(self):
        ctx = ScanContext()
        ctx.add_finding(Finding(
            title="<script>alert(1)</script>",
            severity=Severity.HIGH,
            module="Test",
        ))
        html = to_html(ctx)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ------------------------------------------------------------------
# JUnit XML report
# ------------------------------------------------------------------

class TestJunitReport:

    def test_valid_xml(self):
        ctx = _make_ctx(Severity.HIGH, Severity.LOW)
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuites"

    def test_testsuites_count(self):
        ctx = _make_ctx(Severity.CRITICAL)
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        assert root.get("tests") == "1"

    def test_high_critical_are_failures(self):
        ctx = _make_ctx(Severity.CRITICAL, Severity.HIGH, Severity.LOW)
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.get("failures") == "2"

    def test_testcase_names(self):
        ctx = _make_ctx(Severity.MEDIUM)
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        tc = root.find(".//testcase")
        assert tc is not None
        assert tc.get("name") == "Finding 0"

    def test_medium_gets_system_err(self):
        ctx = _make_ctx(Severity.MEDIUM)
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        err = root.find(".//system-err")
        assert err is not None

    def test_grouped_by_module(self):
        ctx = ScanContext()
        ctx.add_finding(Finding(title="A", severity=Severity.HIGH, module="ModA"))
        ctx.add_finding(Finding(title="B", severity=Severity.LOW, module="ModB"))
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        suites = root.findall("testsuite")
        names = {s.get("name") for s in suites}
        assert names == {"ModA", "ModB"}

    def test_empty_findings(self):
        ctx = _make_ctx()
        xml_str = to_junit(ctx)
        root = ET.fromstring(xml_str)
        assert root.get("tests") == "0"
