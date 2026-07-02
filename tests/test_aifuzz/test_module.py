"""Tests for AiFuzzModule — module-level target identification and routing."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Target
from krumpa.aifuzz.module import AiFuzzModule, _AI_TECH_SIGNALS
from krumpa.sneakygits.fingerprint import FingerprintResult


class TestAiFuzzTargetIdentification:
    """Module correctly identifies AI endpoint targets from fingerprint signals."""

    def test_identifies_target_by_ai_api_key(self):
        ctx = ScanContext()
        target = Target(url="https://api.example.com", metadata={"ai_api_key": "sk-test"})
        ctx.add_target(target)

        targets = AiFuzzModule._identify_ai_targets(ctx)
        assert target in targets

    def test_identifies_target_by_ai_model(self):
        ctx = ScanContext()
        target = Target(url="https://api.example.com", metadata={"ai_model": "gpt-4o"})
        ctx.add_target(target)

        targets = AiFuzzModule._identify_ai_targets(ctx)
        assert target in targets

    def test_identifies_target_by_fingerprint_signal(self):
        ctx = ScanContext()
        target = Target(url="https://ollama.internal.example.com:11434")
        ctx.add_target(target)
        # Inject fingerprint signal
        ctx.metadata["fingerprints"] = {
            target.url: FingerprintResult(url=target.url, technologies=["Ollama"])
        }

        targets = AiFuzzModule._identify_ai_targets(ctx)
        assert target in targets

    def test_skips_non_ai_target(self):
        ctx = ScanContext()
        target = Target(url="https://nginx.example.com")
        ctx.add_target(target)
        ctx.metadata["fingerprints"] = {
            target.url: FingerprintResult(url=target.url, technologies=["Nginx", "PHP"])
        }

        targets = AiFuzzModule._identify_ai_targets(ctx)
        assert target not in targets

    def test_returns_empty_when_no_targets(self):
        ctx = ScanContext()
        assert AiFuzzModule._identify_ai_targets(ctx) == []

    def test_ai_tech_signals_populated(self):
        assert "Ollama" in _AI_TECH_SIGNALS
        assert "Gradio" in _AI_TECH_SIGNALS
        assert "OpenAI-compatible API" in _AI_TECH_SIGNALS


@pytest.mark.asyncio
class TestAiFuzzModuleRunSkips:
    """Module returns empty list when no AI targets are found."""

    async def test_skips_non_ai_targets(self):
        module = AiFuzzModule()
        ctx = ScanContext()
        ctx.add_target(Target(url="https://plain-web.example.com"))

        findings = await module.run(ctx)
        assert findings == []

    async def test_skips_empty_context(self):
        module = AiFuzzModule()
        ctx = ScanContext()

        findings = await module.run(ctx)
        assert findings == []
