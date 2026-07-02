"""Tests for TryHarderAgent and AttackPlannerAgent — graceful degradation."""

from __future__ import annotations


from krumpa.core.ai_orchestrator import TryHarderAgent, AttackPlannerAgent, _autogen_available
from krumpa.core import ScanContext


class TestTryHarderAgent:

    def test_returns_empty_when_no_llm_config(self):
        agent = TryHarderAgent(llm_config=None)
        suggestions = agent.suggest_alternatives("SSRF probe blocked by WAF")
        assert isinstance(suggestions, list)
        # Without AutoGen/LLM, should return []
        assert suggestions == []

    def test_returns_empty_when_autogen_missing(self):
        import sys
        from unittest.mock import patch
        with patch.dict(sys.modules, {"autogen": None}):
            agent = TryHarderAgent(llm_config={"config_list": [{"model": "gpt-4o", "api_key": "test"}]})
            suggestions = agent.suggest_alternatives("Blocked by WAF")
            assert isinstance(suggestions, list)


class TestAttackPlannerAgent:

    def test_returns_empty_dict_when_no_llm_config(self):
        agent = AttackPlannerAgent(llm_config=None)
        ctx = ScanContext()
        plan = agent.plan_next_phase(ctx)
        assert plan == {}

    def test_rerank_returns_original_when_no_llm(self):
        from krumpa.core.hvt_scorer import TargetScore
        from krumpa.core import Target

        agent = AttackPlannerAgent(llm_config=None)
        ctx = ScanContext()
        scores = [
            TargetScore(target=Target(url="https://a.example.com"), score=0.9),
            TargetScore(target=Target(url="https://b.example.com"), score=0.5),
        ]

        result = agent.rerank_hvt(scores, ctx)
        # Without LLM, original order is preserved
        assert result is scores
        assert result[0].target.url == "https://a.example.com"


class TestAutogenAvailable:

    def test_returns_bool(self):
        result = _autogen_available()
        assert isinstance(result, bool)

    def test_returns_false_when_module_missing(self):
        import sys
        from unittest.mock import patch
        with patch.dict(sys.modules, {"autogen": None}):
            result = _autogen_available()
            assert result is False
