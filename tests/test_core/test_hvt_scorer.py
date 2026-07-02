"""Tests for HVTScorer — high-value target prioritisation."""

from __future__ import annotations


from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.hvt_scorer import HVTScorer, TargetScore
from krumpa.sneakygits.fingerprint import FingerprintResult


def _ctx_with_target(url: str, technologies: list | None = None, findings: list | None = None) -> ScanContext:
    ctx = ScanContext()
    target = Target(url=url)
    ctx.add_target(target)
    if technologies:
        ctx.metadata.setdefault("fingerprints", {})[url] = FingerprintResult(
            url=url, technologies=technologies
        )
    if findings:
        for f in findings:
            f.target = target
            ctx.add_finding(f)
    return ctx


class TestTargetScoreDataclass:

    def test_to_dict_has_required_keys(self):
        target = Target(url="https://example.com")
        score = TargetScore(target=target, score=0.75, priority="high", signals=["test signal"])
        d = score.to_dict()
        assert d["target_url"] == "https://example.com"
        assert d["score"] == 0.75
        assert d["priority"] == "high"
        assert "test signal" in d["signals"]


class TestHVTScorer:

    def test_payment_tech_gets_high_score(self):
        ctx = _ctx_with_target("https://checkout.example.com", technologies=["Stripe"])
        scores = HVTScorer().score(ctx)
        assert scores[0].score >= 0.4
        assert any("Payment" in s for s in scores[0].signals)

    def test_ai_endpoint_gets_score(self):
        ctx = _ctx_with_target("https://ai.example.com", technologies=["Ollama"])
        scores = HVTScorer().score(ctx)
        assert scores[0].score >= 0.2
        assert any("AI" in s or "inference" in s.lower() for s in scores[0].signals)

    def test_payment_url_keyword_adds_score(self):
        ctx = _ctx_with_target("https://example.com/payment/process")
        scores = HVTScorer().score(ctx)
        assert scores[0].score >= 0.3

    def test_critical_findings_escalate_score(self):
        finding = Finding(title="SSRF", severity=Severity.CRITICAL, tags=["ssrf"])
        ctx = _ctx_with_target("https://target.example.com", findings=[finding])
        scores = HVTScorer().score(ctx)
        assert scores[0].score >= 0.15
        assert any("CRITICAL" in s for s in scores[0].signals)

    def test_scores_stored_in_context(self):
        ctx = _ctx_with_target("https://example.com")
        HVTScorer().score(ctx)
        assert "hvt_scores" in ctx.metadata
        assert isinstance(ctx.metadata["hvt_scores"], list)

    def test_results_sorted_highest_first(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://boring.example.com"))
        ctx.add_target(Target(url="https://payment.example.com"))
        ctx.metadata["fingerprints"] = {
            "https://payment.example.com": FingerprintResult(
                url="https://payment.example.com", technologies=["Stripe"]
            )
        }
        scores = HVTScorer().score(ctx)
        assert scores[0].score >= scores[1].score

    def test_priority_buckets(self):
        ctx = _ctx_with_target("https://admin.payment.example.com", technologies=["Stripe", "Auth0"])
        scores = HVTScorer().score(ctx)
        assert scores[0].priority in ("critical", "high", "medium", "low")

    def test_empty_context_returns_empty(self):
        ctx = ScanContext()
        scores = HVTScorer().score(ctx)
        assert scores == []

    def test_chain_participation_adds_score(self):
        from krumpa.core.attack_chain import AttackChain
        target = Target(url="https://target.example.com")
        f = Finding(title="SSRF", severity=Severity.HIGH, tags=["ssrf"], target=target)
        ctx = ScanContext()
        ctx.add_target(target)
        ctx.add_finding(f)

        # Simulate an attack chain that includes this finding
        ctx.metadata["attack_chains"] = [
            AttackChain(title="SSRF chain", steps=[f], blast_radius="critical")
        ]

        scores = HVTScorer().score(ctx)
        chain_signals = [s for s in scores[0].signals if "chain" in s.lower()]
        assert len(chain_signals) >= 1
