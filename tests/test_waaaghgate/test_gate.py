"""Tests for krumpa.waaaghgate.gate — quality-gate policy engine."""

import pytest
from krumpa.core import Finding, Severity, Target
from krumpa.waaaghgate.gate import GatePolicy, GateResult, PolicyViolation


def _finding(sev: Severity, **kw) -> Finding:
    return Finding(
        title=f"{sev.value} finding",
        severity=sev,
        target=Target(url="https://example.com"),
        **kw,
    )


class TestGatePolicyDefaults:
    def test_passes_with_no_findings(self):
        result = GatePolicy().evaluate([])
        assert result.passed
        assert result.exit_code == 0

    def test_fails_on_one_critical(self):
        result = GatePolicy().evaluate([_finding(Severity.CRITICAL)])
        assert not result.passed
        assert result.exit_code == 1

    def test_allows_up_to_five_high(self):
        findings = [_finding(Severity.HIGH) for _ in range(5)]
        result = GatePolicy().evaluate(findings)
        assert result.passed

    def test_fails_on_six_high(self):
        findings = [_finding(Severity.HIGH) for _ in range(6)]
        result = GatePolicy().evaluate(findings)
        assert not result.passed


class TestCustomPolicy:
    def test_custom_thresholds(self):
        policy = GatePolicy(fail_on={Severity.MEDIUM: 2})
        findings = [_finding(Severity.MEDIUM) for _ in range(3)]
        result = policy.evaluate(findings)
        assert not result.passed
        assert len(result.violations) == 1

    def test_total_threshold(self):
        policy = GatePolicy(fail_on={}, fail_on_total=5)
        findings = [_finding(Severity.LOW) for _ in range(6)]
        result = policy.evaluate(findings)
        assert not result.passed

    def test_total_threshold_passes(self):
        policy = GatePolicy(fail_on={}, fail_on_total=10)
        findings = [_finding(Severity.LOW) for _ in range(5)]
        result = policy.evaluate(findings)
        assert result.passed


class TestWarnings:
    def test_warn_threshold(self):
        policy = GatePolicy(
            fail_on={},
            warn_on={Severity.LOW: 1},
        )
        findings = [_finding(Severity.LOW) for _ in range(3)]
        result = policy.evaluate(findings)
        assert result.passed  # warnings don't fail
        assert len(result.warnings) == 1

    def test_no_warning_below_threshold(self):
        policy = GatePolicy(fail_on={}, warn_on={Severity.LOW: 10})
        findings = [_finding(Severity.LOW)]
        result = policy.evaluate(findings)
        assert result.warnings == []


class TestIgnoreTags:
    def test_ignores_tagged_findings(self):
        policy = GatePolicy(
            fail_on={Severity.CRITICAL: 0},
            ignore_tags=["false-positive"],
        )
        f = _finding(Severity.CRITICAL, tags=["false-positive"])
        result = policy.evaluate([f])
        assert result.passed

    def test_does_not_ignore_untagged(self):
        policy = GatePolicy(
            fail_on={Severity.CRITICAL: 0},
            ignore_tags=["false-positive"],
        )
        f = _finding(Severity.CRITICAL, tags=["real"])
        result = policy.evaluate([f])
        assert not result.passed


class TestGateResult:
    def test_summary_contains_status(self):
        result = GatePolicy().evaluate([])
        assert "PASSED" in result.summary

    def test_summary_contains_failed(self):
        result = GatePolicy().evaluate([_finding(Severity.CRITICAL)])
        assert "FAILED" in result.summary

    def test_violations_have_message(self):
        result = GatePolicy().evaluate([_finding(Severity.CRITICAL)])
        assert result.violations[0].message
