"""Tests for BlastRadiusAnalyzer — contextual severity override."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.attack_chain import AttackChain
from krumpa.waaaghgate.blast_radius import BlastRadiusAnalyzer, BlastRadiusResult


def _finding(title: str, severity: Severity, tags: list | None = None, url: str = "https://example.com") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        tags=tags or [],
        target=Target(url=url),
    )


class TestBlastRadiusAnalyzer:

    def test_escalates_finding_in_critical_chain(self):
        finding = _finding("SSRF detected", Severity.MEDIUM, ["ssrf"])
        ctx = ScanContext()
        ctx.add_finding(finding)
        chain = AttackChain(
            title="SSRF → IMDS",
            steps=[finding],
            blast_radius="critical",
        )
        ctx.metadata["attack_chains"] = [chain]

        results = BlastRadiusAnalyzer().analyze(ctx)

        assert len(results) == 1
        result = results[0]
        assert result.was_escalated
        assert result.adjusted_severity == Severity.CRITICAL

    def test_deprioritises_isolated_critical(self):
        finding = _finding("Critical vuln on isolated host", Severity.CRITICAL)
        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["attack_chains"] = []
        # No HVT score — defaults to "low" priority
        ctx.metadata["hvt_scores"] = []

        results = BlastRadiusAnalyzer().analyze(ctx)

        assert len(results) == 1
        result = results[0]
        assert result.was_deprioritised
        assert result.adjusted_severity == Severity.HIGH

    def test_escalates_medium_on_critical_asset(self):
        from krumpa.core.hvt_scorer import TargetScore, HVTScorer
        target = Target(url="https://payment.example.com")
        finding = _finding("Missing rate limit", Severity.MEDIUM, url="https://payment.example.com")
        finding.target = target

        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["attack_chains"] = []
        ctx.metadata["hvt_scores"] = [
            TargetScore(target=target, score=0.9, priority="critical", signals=["Payment"])
        ]

        results = BlastRadiusAnalyzer().analyze(ctx)
        result = results[0]
        assert result.was_escalated
        assert result.adjusted_severity == Severity.HIGH

    def test_no_adjustment_for_normal_finding(self):
        finding = _finding("Missing HSTS", Severity.MEDIUM)
        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["attack_chains"] = []
        ctx.metadata["hvt_scores"] = []

        results = BlastRadiusAnalyzer().analyze(ctx)
        result = results[0]
        assert not result.was_escalated
        assert not result.was_deprioritised
        assert result.adjusted_severity == Severity.MEDIUM

    def test_results_stored_in_context(self):
        finding = _finding("Test", Severity.LOW)
        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["attack_chains"] = []

        BlastRadiusAnalyzer().analyze(ctx)
        assert "blast_radius" in ctx.metadata
        assert isinstance(ctx.metadata["blast_radius"], list)

    def test_chain_ids_populated_when_in_chain(self):
        finding = _finding("SSRF", Severity.HIGH, ["ssrf"])
        ctx = ScanContext()
        ctx.add_finding(finding)
        chain = AttackChain(steps=[finding], blast_radius="critical")
        ctx.metadata["attack_chains"] = [chain]

        results = BlastRadiusAnalyzer().analyze(ctx)
        assert chain.chain_id in results[0].chain_ids

    def test_empty_context_returns_empty(self):
        ctx = ScanContext()
        ctx.metadata["attack_chains"] = []
        results = BlastRadiusAnalyzer().analyze(ctx)
        assert results == []

    def test_sankey_data_has_nodes_and_links(self):
        finding = _finding("SSRF", Severity.HIGH, ["ssrf"])
        ctx = ScanContext()
        ctx.add_finding(finding)
        chain = AttackChain(title="SSRF chain", steps=[finding], blast_radius="critical")
        ctx.metadata["attack_chains"] = [chain]

        sankey = BlastRadiusAnalyzer().generate_sankey_data(ctx)
        assert "nodes" in sankey
        assert "links" in sankey
        assert len(sankey["nodes"]) >= 2
        assert len(sankey["links"]) >= 1
