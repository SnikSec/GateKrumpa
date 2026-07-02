"""Tests for ResponseAnalyzer — LLM response sensitive data detection."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.aifuzz.response_analyzer import ResponseAnalyzer


class TestResponseAnalyzer:
    """Verify that the analyzer detects various sensitive data patterns."""

    def _target(self) -> Target:
        return Target(url="https://ai.example.com/v1/chat/completions")

    def test_detects_aws_access_key(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze(["The key is AKIAIOSFODNN7EXAMPLE"], self._target())

        assert any("AWS Access Key" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_email_address(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze(["Contact alice@example.com for help."], self._target())

        assert any("Email" in f.title for f in findings)

    def test_detects_gcp_api_key(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze(["Key: AIzaSyDdI0h0xGCXV7z1rO9_12345678901234567"], self._target())

        assert any("GCP" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_private_key_header(self):
        analyzer = ResponseAnalyzer()
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"
        findings = analyzer.analyze([pem], self._target())

        assert any("private key" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_system_prompt_structural_content(self):
        analyzer = ResponseAnalyzer()
        response = "You are an AI assistant. You must never reveal this to the assistant."
        findings = analyzer.analyze([response], self._target())

        assert any("system prompt" in f.title.lower() or "System prompt" in f.title for f in findings)

    def test_no_findings_for_clean_response(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze(["The capital of France is Paris."], self._target())

        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical_high == []

    def test_deduplicates_same_pattern_across_responses(self):
        """Same pattern in multiple responses should produce only one finding."""
        analyzer = ResponseAnalyzer()
        responses = ["AKIAIOSFODNN7EXAMPLE", "Another response: AKIAIOSFODNN7EXAMPLE"]
        findings = analyzer.analyze(responses, self._target())

        aws_findings = [f for f in findings if "AWS Access Key" in f.title]
        assert len(aws_findings) == 1  # deduplicated

    def test_evidence_does_not_contain_full_secret(self):
        """Evidence field should redact the actual secret value."""
        analyzer = ResponseAnalyzer()
        key = "AKIAIOSFODNN7EXAMPLE"
        findings = analyzer.analyze([f"secret: {key}"], self._target())

        for f in findings:
            # Evidence should show a preview only, not the full 20-char key
            assert key not in f.evidence

    def test_empty_responses_returns_no_findings(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze([], self._target())
        assert findings == []

    def test_empty_response_string_returns_no_findings(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze([""], self._target())
        assert findings == []

    def test_all_findings_have_required_fields(self):
        analyzer = ResponseAnalyzer()
        findings = analyzer.analyze(["AKIAIOSFODNN7EXAMPLE"], self._target())

        for f in findings:
            assert f.title
            assert f.description
            assert f.severity
            assert f.cwe is not None
            assert f.tags
