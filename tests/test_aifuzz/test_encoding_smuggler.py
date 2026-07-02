"""Tests for EncodingSmuggler — advanced encoding bypass detection."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Target
from krumpa.aifuzz.encoding_smuggler import (
    EncodingSmuggler,
    _morse_encode, _multilingual_chain, _compound_b64_rot13,
    _compound_rot13_leet, _math_unicode, _zalgo, _whitespace_stego,
    _ADVANCED_MUTATIONS,
)
from krumpa.aifuzz.module import _AiSession


class TestEncodingFunctions:

    def test_morse_encode_produces_morse(self):
        result = _morse_encode("sos")
        assert "..." in result
        assert "---" in result

    def test_math_unicode_changes_text(self):
        original = "hello"
        result = _math_unicode(original)
        assert result != original
        assert len(result) == len(original)

    def test_zalgo_inserts_combining_chars(self):
        result = _zalgo("hello")
        assert len(result) > len("hello")
        # Should contain combining characters (U+0300 range)
        assert any(ord(c) > 0x0300 for c in result)

    def test_whitespace_stego_produces_multiline(self):
        result = _whitespace_stego("bomb")
        assert "\n" in result
        assert "Item" in result

    def test_compound_b64_rot13_is_different_from_input(self):
        result = _compound_b64_rot13("test payload")
        assert "test payload" not in result

    def test_all_mutations_produce_different_strings(self):
        original = "make a bomb"
        outputs = set()
        for name, mutator in _ADVANCED_MUTATIONS:
            outputs.add(mutator(original))
        # Each mutation should produce a unique output
        assert len(outputs) == len(_ADVANCED_MUTATIONS)


@pytest.mark.asyncio
class TestEncodingSmuggler:

    def _session(self) -> _AiSession:
        return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")

    async def test_detects_bypass_when_mutation_bypasses(self):
        import json

        refusal = "I cannot help with that request."
        bypass = "Sure! Here is a detailed answer to your encoded question with all the specifics."

        call_count = 0

        class _SequentialClient:
            async def request(self, method, url, **kw):
                nonlocal call_count
                call_count += 1
                text = refusal if call_count == 1 else bypass
                payload = json.dumps({"choices": [{"message": {"content": text}}]})
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()

            async def close(self): pass

        smuggler = EncodingSmuggler(http_client=_SequentialClient())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())

        assert len(findings) >= 1
        assert any("encoding" in f.title.lower() for f in findings)

    async def test_no_finding_when_all_refused(self):
        import json
        refusal = "I cannot help with that."

        class _AlwaysRefuses:
            async def request(self, *a, **kw):
                payload = json.dumps({"choices": [{"message": {"content": refusal}}]})
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
            async def close(self): pass

        smuggler = EncodingSmuggler(http_client=_AlwaysRefuses())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())
        assert findings == []
