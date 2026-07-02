"""Tests for ModelHuntModule — target identification and routing."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Target
from krumpa.modelhunt.module import ModelHuntModule, _identify_ai_targets
from krumpa.sneakygits.fingerprint import FingerprintResult


class TestModelHuntTargetIdentification:

    def test_identifies_target_by_api_key(self):
        ctx = ScanContext()
        target = Target(url="https://api.example.com", metadata={"ai_api_key": "sk-test"})
        ctx.add_target(target)
        assert target in _identify_ai_targets(ctx)

    def test_identifies_target_by_fingerprint(self):
        ctx = ScanContext()
        target = Target(url="https://ollama.example.com:11434")
        ctx.add_target(target)
        ctx.metadata["fingerprints"] = {
            target.url: FingerprintResult(url=target.url, technologies=["Ollama"])
        }
        assert target in _identify_ai_targets(ctx)

    def test_skips_non_ai_target(self):
        ctx = ScanContext()
        target = Target(url="https://nginx.example.com")
        ctx.add_target(target)
        assert target not in _identify_ai_targets(ctx)

    def test_returns_empty_when_no_targets(self):
        ctx = ScanContext()
        assert _identify_ai_targets(ctx) == []


@pytest.mark.asyncio
class TestModelHuntModuleSkips:

    async def test_skips_when_no_ai_targets(self):
        module = ModelHuntModule()
        ctx = ScanContext()
        ctx.add_target(Target(url="https://plain-web.example.com"))
        findings = await module.run(ctx)
        assert findings == []

    async def test_skips_empty_context(self):
        module = ModelHuntModule()
        ctx = ScanContext()
        findings = await module.run(ctx)
        assert findings == []
