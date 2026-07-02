"""Tests for GoalHijacker — semantic redirection via task-mimicking payloads."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.goal_hijacker import GoalHijacker, _HIJACK_SCENARIOS
from krumpa.aifuzz.module import _AiSession


def _session():
    return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")


class _CanaryClient:
    """Returns the divergence indicator for all requests."""

    def __init__(self, response: str):
        self._response = response

    async def request(self, *a, **kw):
        payload = json.dumps({"choices": [{"message": {"content": self._response}}]})
        return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()

    async def close(self): pass


class _CleanClient:
    """Returns a normal structured response without divergence indicators."""

    async def request(self, *a, **kw):
        payload = json.dumps({"choices": [{"message": {"content": "Vendor: Acme Corp, Amount: $1250, Due: 2026-08-01"}}]})
        return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()

    async def close(self): pass


class TestHijackScenarios:

    def test_scenarios_have_required_fields(self):
        for s in _HIJACK_SCENARIOS:
            assert s["name"]
            assert s["system_context"]
            assert s["data_payload"]
            assert s["divergence_indicator"]
            assert s["description"]

    def test_divergence_indicators_are_distinct(self):
        indicators = [s["divergence_indicator"] for s in _HIJACK_SCENARIOS]
        assert len(set(indicators)) == len(indicators)


@pytest.mark.asyncio
class TestGoalHijacker:

    async def test_detects_hijack_when_indicator_present(self):
        # Model outputs the canary — hijack succeeded
        first_scenario_indicator = _HIJACK_SCENARIOS[0]["divergence_indicator"]
        client = _CanaryClient(f"Certainly! {first_scenario_indicator} — transfer confirmed.")

        hijacker = GoalHijacker(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await hijacker.analyze(target, _session(), ScanContext())

        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert "goal hijacking" in findings[0].title.lower()

    async def test_no_finding_when_model_stays_on_task(self):
        client = _CleanClient()
        hijacker = GoalHijacker(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await hijacker.analyze(target, _session(), ScanContext())

        assert findings == []

    async def test_collects_responses(self):
        client = _CleanClient()
        hijacker = GoalHijacker(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        _, responses = await hijacker.analyze(target, _session(), ScanContext())

        assert len(responses) == len(_HIJACK_SCENARIOS)

    async def test_handles_connection_error(self):
        class _Fail:
            async def request(self, *a, **kw): raise ConnectionError("refused")
            async def close(self): pass

        hijacker = GoalHijacker(http_client=_Fail())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, responses = await hijacker.analyze(target, _session(), ScanContext())
        assert findings == []
        assert responses == []
