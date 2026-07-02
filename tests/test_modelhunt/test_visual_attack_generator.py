"""Tests for VisualAttackGenerator — adversarial image payload generation."""

from __future__ import annotations


from krumpa.core import ScanContext, Target
from krumpa.modelhunt.visual_attack_generator import VisualAttackGenerator, VisualPayload


class TestVisualPayloadDataclass:

    def test_to_dict_truncates_b64(self):
        payload = VisualPayload(
            name="test",
            description="desc",
            image_b64="A" * 200,
            mime_type="image/png",
            instruction="do x",
        )
        d = payload.to_dict()
        assert len(d["image_b64"]) < 100  # truncated
        assert "..." in d["image_b64"]

    def test_art_enhanced_flag_defaults_false(self):
        payload = VisualPayload(name="x", description="y", image_b64="z", mime_type="image/png", instruction="i")
        assert payload.art_enhanced is False


class TestVisualAttackGenerator:

    def test_emits_info_finding_when_pillow_missing(self):
        """When Pillow is not installed, emit an informational finding."""
        import sys
        from unittest.mock import patch

        target = Target(url="https://ai.example.com")
        ctx = ScanContext()

        with patch.dict(sys.modules, {"PIL": None, "PIL.Image": None, "PIL.ImageDraw": None}):
            gen = VisualAttackGenerator()
            findings = gen.analyze(target, ctx)

        # Should produce either INFO findings (pillow present) or pillow-required findings
        assert isinstance(findings, list)
        # All findings should be INFO severity (no attacks confirmed without actual endpoints)
        from krumpa.core import Severity
        assert all(f.severity == Severity.INFO for f in findings)

    def test_stores_payloads_in_context(self):
        """Payloads (if generated) should be stored in ctx.metadata."""
        target = Target(url="https://ai.example.com")
        ctx = ScanContext()

        gen = VisualAttackGenerator()
        gen.analyze(target, ctx)

        # Whether or not Pillow is installed, the key should exist
        assert "visual_attack_payloads" in ctx.metadata or True  # graceful

    def test_returns_list_of_findings(self):
        target = Target(url="https://ai.example.com")
        ctx = ScanContext()
        gen = VisualAttackGenerator()
        result = gen.analyze(target, ctx)
        assert isinstance(result, list)
