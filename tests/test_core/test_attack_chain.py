"""Tests for AttackChainBuilder — multi-step attack path correlation."""

from __future__ import annotations


from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.attack_chain import AttackChain, AttackChainBuilder


def _finding(title: str, severity: Severity, tags: list, url: str = "https://example.com") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        tags=tags,
        target=Target(url=url),
    )


class TestAttackChainDataclass:

    def test_entry_point_is_first_step(self):
        f1 = _finding("A", Severity.HIGH, [])
        f2 = _finding("B", Severity.CRITICAL, [])
        chain = AttackChain(steps=[f1, f2])
        assert chain.entry_point is f1

    def test_terminal_impact_is_last_step(self):
        f1 = _finding("A", Severity.HIGH, [])
        f2 = _finding("B", Severity.CRITICAL, [])
        chain = AttackChain(steps=[f1, f2])
        assert chain.terminal_impact is f2

    def test_empty_chain_returns_none(self):
        chain = AttackChain()
        assert chain.entry_point is None
        assert chain.terminal_impact is None

    def test_to_dict_has_required_keys(self):
        chain = AttackChain(title="Test", description="Desc", confidence=0.8, blast_radius="high")
        d = chain.to_dict()
        assert "chain_id" in d
        assert d["title"] == "Test"
        assert d["confidence"] == 0.8
        assert d["blast_radius"] == "high"


class TestAttackChainBuilder:

    def test_ssrf_to_imds_chain(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("SSRF detected", Severity.HIGH, ["ssrf"]))
        ctx.add_finding(_finding("IMDSv1 enabled", Severity.HIGH, ["cloud", "aws", "imds", "imdsv1"]))

        builder = AttackChainBuilder()
        chains = builder.build(ctx)

        ssrf_chains = [c for c in chains if "ssrf" in c.title.lower()]
        assert len(ssrf_chains) >= 1
        assert ssrf_chains[0].blast_radius == "critical"
        assert ssrf_chains[0].confidence > 0.4

    def test_iam_privesc_to_s3_chain(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("IAM privilege escalation path", Severity.CRITICAL, ["cloud", "aws", "iam", "privesc", "privilege-escalation"]))
        ctx.add_finding(_finding("S3 public bucket policy", Severity.CRITICAL, ["cloud", "aws", "s3", "public-access", "data-exposure"]))

        chains = AttackChainBuilder().build(ctx)
        iam_chains = [c for c in chains if "iam" in c.title.lower()]
        assert len(iam_chains) >= 1

    def test_prompt_injection_to_data_leak_chain(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("Prompt injection succeeded", Severity.HIGH, ["ai", "prompt-injection", "llm"]))
        ctx.add_finding(_finding("AWS key in model response", Severity.CRITICAL, ["ai", "data-leakage", "credential"]))

        chains = AttackChainBuilder().build(ctx)
        ai_chains = [c for c in chains if "prompt" in c.title.lower()]
        assert len(ai_chains) >= 1
        assert ai_chains[0].confidence >= 0.7

    def test_vector_db_chain(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("Exposed vector DB", Severity.CRITICAL, ["ai", "vector-db", "unauthenticated"]))

        chains = AttackChainBuilder().build(ctx)
        vdb_chains = [c for c in chains if "vector" in c.title.lower()]
        assert len(vdb_chains) >= 1
        assert vdb_chains[0].blast_radius == "critical"

    def test_chains_stored_in_context_metadata(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("SSRF", Severity.HIGH, ["ssrf"]))

        AttackChainBuilder().build(ctx)
        assert "attack_chains" in ctx.metadata
        assert isinstance(ctx.metadata["attack_chains"], list)

    def test_no_chains_when_no_correlatable_findings(self):
        ctx = ScanContext()
        ctx.add_finding(_finding("Missing HSTS", Severity.LOW, ["security-header"]))
        ctx.add_finding(_finding("Weak password policy", Severity.MEDIUM, ["auth"]))

        chains = AttackChainBuilder().build(ctx)
        assert chains == []

    def test_empty_context_returns_empty(self):
        ctx = ScanContext()
        chains = AttackChainBuilder().build(ctx)
        assert chains == []
