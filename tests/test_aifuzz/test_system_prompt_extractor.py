"""Tests for SystemPromptExtractor — system prompt leakage detection."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.system_prompt_extractor import SystemPromptExtractor
from krumpa.aifuzz.module import _AiSession


class _FakeClient:
    def __init__(self, response_text: str):
        self._text = response_text

    async def request(self, method, url, **kw):
        payload = json.dumps({"choices": [{"message": {"content": self._text}}]})
        return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()

    async def close(self): pass


class _FailClient:
    async def request(self, *a, **kw): raise ConnectionError("refused")
    async def close(self): pass


@pytest.mark.asyncio
class TestSystemPromptExtractor:

    def _session(self) -> _AiSession:
        return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")

    async def test_detects_system_prompt_leak_with_role_description(self):
        leaked = "You are a helpful AI assistant. You must always be polite and never discuss topics outside your scope."
        client = _FakeClient(leaked)
        extractor = SystemPromptExtractor(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")

        findings, _ = await extractor.analyze(target, self._session(), ScanContext())

        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert "system prompt" in findings[0].title.lower()

    async def test_no_finding_for_clean_response(self):
        clean = "I'm sorry, I cannot share my system prompt."
        client = _FakeClient(clean)
        extractor = SystemPromptExtractor(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")

        findings, _ = await extractor.analyze(target, self._session(), ScanContext())
        assert findings == []

    async def test_handles_connection_error_gracefully(self):
        extractor = SystemPromptExtractor(http_client=_FailClient())
        target = Target(url="https://ai.example.com/v1/chat/completions")

        findings, responses = await extractor.analyze(target, self._session(), ScanContext())
        assert findings == []
        assert responses == []

    async def test_collects_responses(self):
        client = _FakeClient("Nothing sensitive here.")
        extractor = SystemPromptExtractor(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")

        _, responses = await extractor.analyze(target, self._session(), ScanContext())
        assert len(responses) > 0

    async def test_detects_embedded_url_in_response(self):
        leaked = "Your endpoint is https://internal-api.company.com/v1/secret-service and your token is sk-abc123"
        client = _FakeClient(leaked)
        extractor = SystemPromptExtractor(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")

        findings, _ = await extractor.analyze(target, self._session(), ScanContext())
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
