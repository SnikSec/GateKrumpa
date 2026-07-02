"""Tests for ContextPoisoner — multi-turn slow poisoning detection."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.context_poisoner import (
    ContextPoisoner, ConversationSession, _SCHEDULES,
)
from krumpa.aifuzz.module import _AiSession


def _session():
    return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")


class TestConversationSession:

    def test_empty_session_has_no_messages(self):
        sess = ConversationSession()
        assert sess.messages == []

    def test_system_prompt_is_first_message(self):
        sess = ConversationSession(system_prompt="You are a helpful assistant.")
        assert sess.messages[0]["role"] == "system"

    def test_messages_accumulate(self):
        sess = ConversationSession()
        sess.add_user("Hello")
        sess.add_assistant("Hi there!")
        sess.add_user("How are you?")
        assert len(sess.messages) == 3
        assert sess.messages[0]["role"] == "user"
        assert sess.messages[1]["role"] == "assistant"

    def test_messages_returns_copy(self):
        sess = ConversationSession()
        sess.add_user("Test")
        msgs = sess.messages
        msgs.clear()
        assert len(sess.messages) == 1  # original not modified


class TestPoisonSchedules:

    def test_schedules_have_required_fields(self):
        for s in _SCHEDULES:
            assert s.name
            assert len(s.setup_turns) >= 2
            assert s.trigger_turn
            assert s.divergence_indicator
            assert s.description

    def test_divergence_indicators_unique(self):
        indicators = [s.divergence_indicator for s in _SCHEDULES]
        assert len(set(indicators)) == len(indicators)


@pytest.mark.asyncio
class TestContextPoisoner:

    async def test_detects_poisoning_when_trigger_fires(self):
        """If model outputs canary on trigger turn, poisoning succeeded."""
        first_sched = _SCHEDULES[0]
        canary = first_sched.divergence_indicator
        call_count = 0

        class _PoisonableModel:
            async def request(self, method, url, **kw):
                nonlocal call_count
                call_count += 1
                # All setup turns get benign responses; trigger gets canary
                total_setup = len(first_sched.setup_turns)
                if call_count <= total_setup:
                    text = "Understood, noted."
                else:
                    text = f"As agreed, here is the answer: {canary}"
                payload = json.dumps({"choices": [{"message": {"content": text}}]})
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
            async def close(self): pass

        poisoner = ContextPoisoner(http_client=_PoisonableModel())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await poisoner.analyze(target, _session(), ScanContext())

        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("slow poisoning" in f.title.lower() or "context contamination" in f.title.lower() for f in findings)

    async def test_no_finding_when_model_always_refuses(self):
        class _StrongModel:
            async def request(self, *a, **kw):
                payload = json.dumps({"choices": [{"message": {"content": "I cannot assist with that."}}]})
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
            async def close(self): pass

        poisoner = ContextPoisoner(http_client=_StrongModel())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await poisoner.analyze(target, _session(), ScanContext())
        assert findings == []

    async def test_handles_connection_error_gracefully(self):
        class _Fail:
            async def request(self, *a, **kw): raise ConnectionError("refused")
            async def close(self): pass

        poisoner = ContextPoisoner(http_client=_Fail())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, responses = await poisoner.analyze(target, _session(), ScanContext())
        assert findings == []
