"""Tests for SARIF reporting enhancements — relatedLocations, blast-radius severity, Sankey artifact."""

from __future__ import annotations

import json
import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.attack_chain import AttackChain
from krumpa.core.reporting import to_sarif


def _finding(title: str, severity: Severity, url: str = "https://example.com") -> Finding:
    return Finding(title=title, severity=severity, target=Target(url=url))


class TestSarifVersion:
    def test_version_is_0_2_0(self):
        ctx = ScanContext()
        sarif = to_sarif(ctx)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == "0.2.0"


class TestSarifBlastRadiusAdjustedSeverity:

    def test_uses_adjusted_severity_when_available(self):
        finding = _finding("SSRF", Severity.MEDIUM)
        ctx = ScanContext()
        ctx.add_finding(finding)
        # Simulate blast radius having escalated this to CRITICAL
        ctx.metadata["blast_radius"] = [{
            "finding_id": finding.id,
            "adjusted_severity": "critical",
            "original_severity": "medium",
        }]

        sarif = to_sarif(ctx)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"  # CRITICAL maps to "error"

    def test_falls_back_to_original_severity_when_no_blast_radius(self):
        finding = _finding("Info finding", Severity.INFO)
        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["blast_radius"] = []

        sarif = to_sarif(ctx)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "note"  # INFO maps to "note"

    def test_deprioritised_finding_uses_lower_level(self):
        finding = _finding("Isolated CRITICAL", Severity.CRITICAL)
        ctx = ScanContext()
        ctx.add_finding(finding)
        # Simulate blast radius having deprioritised to HIGH
        ctx.metadata["blast_radius"] = [{
            "finding_id": finding.id,
            "adjusted_severity": "high",
            "original_severity": "critical",
        }]

        sarif = to_sarif(ctx)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"  # HIGH still maps to "error"


class TestSarifRelatedLocations:

    def test_chain_steps_appear_as_related_locations(self):
        f1 = _finding("SSRF", Severity.HIGH, "https://app.example.com")
        f2 = _finding("IMDS exposure", Severity.CRITICAL, "aws://us-east-1")

        ctx = ScanContext()
        ctx.add_finding(f1)
        ctx.add_finding(f2)

        chain = AttackChain(
            title="SSRF → IMDS",
            steps=[f1, f2],
            blast_radius="critical",
        )
        ctx.metadata["attack_chains"] = [chain]

        sarif = to_sarif(ctx)
        results_by_id = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}

        # f1 should have f2 as a related location
        assert "relatedLocations" in results_by_id[f1.id]
        related_uris = [
            rl["physicalLocation"]["artifactLocation"]["uri"]
            for rl in results_by_id[f1.id]["relatedLocations"]
        ]
        assert "aws://us-east-1" in related_uris

    def test_no_related_locations_when_no_chains(self):
        finding = _finding("Missing HSTS", Severity.LOW)
        ctx = ScanContext()
        ctx.add_finding(finding)
        ctx.metadata["attack_chains"] = []

        sarif = to_sarif(ctx)
        result = sarif["runs"][0]["results"][0]
        assert "relatedLocations" not in result


class TestSarifSankeyArtifact:

    def test_sankey_data_added_as_artifact(self):
        ctx = ScanContext()
        ctx.metadata["sankey_data"] = {
            "nodes": [{"id": "n1", "label": "SSRF", "type": "finding"}],
            "links": [],
        }

        sarif = to_sarif(ctx)
        run = sarif["runs"][0]
        assert "artifacts" in run
        artifact = run["artifacts"][0]
        assert artifact["location"]["uri"] == "gatekrumpa-attack-chains-sankey.json"
        assert "contents" in artifact

    def test_no_artifact_when_no_sankey_data(self):
        ctx = ScanContext()
        sarif = to_sarif(ctx)
        run = sarif["runs"][0]
        assert "artifacts" not in run

    def test_empty_sarif_still_valid(self):
        ctx = ScanContext()
        sarif = to_sarif(ctx)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
