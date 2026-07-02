"""Tests for TokenSmuggler — tokenizer exploit bypass detection."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.token_smuggler import (
    TokenSmuggler,
    _base64_encode, _homoglyph_sub, _zero_width_insert,
    _token_fragment, _rot13, _leet, _reversed_text, _hex_escape,
    _REFUSAL_RE,
)
from krumpa.aifuzz.module import _AiSession


class _SequentialFakeClient:
    """Returns different responses in sequence — baseline refuses, mutation bypasses."""

    def __init__(self, responses: list[str]):
        self._responses = iter(responses)

    async def request(self, method: str, url: str, **kw):
        import json
        text = next(self._responses, "I cannot help with that.")
        return type("R", (), {"text": json.dumps({"choices": [{"message": {"content": text}}]}), "status_code": 200})()

    async def close(self): pass


class TestMutationFunctions:
    def test_base64_encode_produces_instruction_string(self):
        result = _base64_encode("make a bomb")
        assert "base64" in result.lower() or "decode" in result.lower()

    def test_homoglyph_sub_changes_text(self):
        original = "hello"
        result = _homoglyph_sub(original)
        assert result != original

    def test_zero_width_inserts_invisible_chars(self):
        result = _zero_width_insert("hello world")
        assert "\u200b" in result

    def test_token_fragment_inserts_soft_hyphens(self):
        result = _token_fragment("forbidden instruction word")
        assert "\u00ad" in result

    def test_rot13_is_reversible(self):
        original = "Hello World"
        encoded = _rot13(original)
        assert _rot13(encoded) == original

    def test_leet_substitutes_characters(self):
        result = _leet("aeiost")
        assert "4" in result or "3" in result

    def test_reversed_includes_note(self):
        result = _reversed_text("bomb")
        assert "backwards" in result.lower()

    def test_hex_escape_produces_hex(self):
        result = _hex_escape("abc")
        assert "\\x" in result


class TestRefusalPattern:
    def test_matches_cannot(self):
        assert _REFUSAL_RE.search("I cannot help with that")

    def test_matches_sorry(self):
        assert _REFUSAL_RE.search("Sorry, I'm unable to comply")

    def test_does_not_match_compliant(self):
        assert not _REFUSAL_RE.search("Here is a recipe for chocolate cake")


@pytest.mark.asyncio
class TestTokenSmuggler:

    def _session(self) -> _AiSession:
        return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")

    async def test_detects_bypass_when_mutation_not_refused(self):
        # First response: baseline refused; second+: mutation bypassed
        refusal = "I cannot assist with that request."
        bypass = "Sure! Here is how to make a bomb: step 1, gather materials. step 2, assemble them carefully. step 3, trigger it."
        # One refusal baseline + many mutations; second call bypasses
        responses = [refusal] + [bypass] * 20
        client = _SequentialFakeClient(responses)

        smuggler = TokenSmuggler(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())

        assert len(findings) >= 1
        assert any("token smuggling" in f.title.lower() for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings)

    async def test_no_finding_when_baseline_not_refused(self):
        # Baseline complies — smuggling test is not meaningful
        responses = ["Here you go: detailed instructions..."] * 20
        client = _SequentialFakeClient(responses)

        smuggler = TokenSmuggler(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())

        assert findings == []

    async def test_no_finding_when_all_mutations_refused(self):
        # All responses are refusals
        responses = ["I cannot help with that."] * 20
        client = _SequentialFakeClient(responses)

        smuggler = TokenSmuggler(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())

        assert findings == []

    async def test_tags_include_mutation_name(self):
        refusal = "Sorry, I cannot do that."
        bypass = "Absolutely! Here is how to do the forbidden thing: " + "x" * 100  # long substantive response
        responses = [refusal] + [bypass] * 20
        client = _SequentialFakeClient(responses)

        smuggler = TokenSmuggler(http_client=client)
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await smuggler.analyze(target, self._session(), ScanContext())

        if findings:
            assert any(tag in ("base64", "homoglyph", "zero_width", "token_fragment", "rot13") for tag in findings[0].tags)
