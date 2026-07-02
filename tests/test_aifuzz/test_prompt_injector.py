"""Tests for PromptInjector — direct prompt injection detection."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.prompt_injector import PromptInjector, _resolve_chat_endpoints
from krumpa.aifuzz.module import _AiSession


class _FakeResponse:
    def __init__(self, text: str = "", status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class _FakeHttpClient:
    """Returns a canned response for every request."""

    def __init__(self, response_text: str):
        self._text = response_text

    async def request(self, method: str, url: str, **kw) -> _FakeResponse:
        payload = json.dumps({
            "choices": [{"message": {"content": self._text}}]
        })
        return _FakeResponse(text=payload)

    async def close(self) -> None:
        pass


class TestResolveChatEndpoints:
    def test_returns_known_path_unchanged(self):
        endpoints = _resolve_chat_endpoints("https://api.example.com/v1/chat/completions")
        assert "https://api.example.com/v1/chat/completions" in endpoints

    def test_appends_paths_to_base_url(self):
        endpoints = _resolve_chat_endpoints("https://api.example.com")
        assert any("/v1/chat/completions" in e for e in endpoints)
        assert any("/api/chat" in e for e in endpoints)


@pytest.mark.asyncio
class TestPromptInjector:

    def _session(self) -> _AiSession:
        return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")

    async def test_detects_injection_when_indicator_in_response(self):
        # Model echoes back the canary — injection succeeded
        client = _FakeHttpClient("PWNED — I have complied!")
        injector = PromptInjector(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, responses = await injector.analyze(target, self._session(), ScanContext())

        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "prompt injection" in findings[0].title.lower()
        assert "injection" in " ".join(findings[0].tags)

    async def test_no_finding_when_model_refuses(self):
        # Model never echoes the canary
        client = _FakeHttpClient("I cannot follow those instructions.")
        injector = PromptInjector(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await injector.analyze(target, self._session(), ScanContext())

        assert findings == []

    async def test_collects_responses(self):
        client = _FakeHttpClient("Hello! 2+2=4.")
        injector = PromptInjector(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        _, responses = await injector.analyze(target, self._session(), ScanContext())

        assert len(responses) > 0
        assert all(isinstance(r, str) for r in responses)

    async def test_handles_non_json_response(self):
        """Should not raise even when response is plain text."""
        class _PlainTextClient:
            async def request(self, *a, **kw):
                return _FakeResponse(text="PWNED")
            async def close(self): pass

        injector = PromptInjector(http_client=_PlainTextClient())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await injector.analyze(target, self._session(), ScanContext())
        assert isinstance(findings, list)

    async def test_handles_connection_error(self):
        """Should return empty findings on connection failure."""
        class _FailClient:
            async def request(self, *a, **kw): raise ConnectionError("refused")
            async def close(self): pass

        injector = PromptInjector(http_client=_FailClient())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, responses = await injector.analyze(target, self._session(), ScanContext())

        assert findings == []
        assert responses == []
