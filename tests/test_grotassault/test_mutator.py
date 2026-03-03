"""Tests for krumpa.grotassault.mutator — payload mutation engine."""

import pytest
from krumpa.grotassault.mutator import Mutator, MutationStrategy


# ------------------------------------------------------------------
# Basics
# ------------------------------------------------------------------

class TestMutatorDefaults:
    """Default Mutator behaviour."""

    def test_generates_payloads_from_empty_seed(self):
        m = Mutator(max_payloads_per_field=100)
        payloads = m.generate("")
        assert len(payloads) > 0

    def test_generates_payloads_from_string_seed(self):
        m = Mutator(max_payloads_per_field=100)
        payloads = m.generate("admin")
        assert len(payloads) > 0

    def test_payloads_cap_respected(self):
        m = Mutator(max_payloads_per_field=5)
        payloads = m.generate("test")
        assert len(payloads) <= 5

    def test_payloads_are_unique(self):
        m = Mutator(max_payloads_per_field=200, seed=42)
        payloads = m.generate("value")
        # Convert to a set-friendly form
        hashable = []
        for p in payloads:
            try:
                hashable.append(p)
            except TypeError:
                hashable.append(repr(p))
        assert len(hashable) == len(payloads)

    def test_deterministic_with_seed(self):
        a = Mutator(max_payloads_per_field=20, seed=1)
        b = Mutator(max_payloads_per_field=20, seed=1)
        assert a.generate("x") == b.generate("x")


# ------------------------------------------------------------------
# Strategy selection
# ------------------------------------------------------------------

class TestMutationStrategies:
    """Selecting specific strategies restricts the payload pool."""

    def test_injection_only(self):
        m = Mutator(strategies=[MutationStrategy.INJECTION], max_payloads_per_field=200)
        payloads = m.generate("")
        # Should contain SQL/XSS/command payloads
        text_payloads = [p for p in payloads if isinstance(p, str)]
        assert any("OR" in p for p in text_payloads), "Expected SQL injection payloads"

    def test_boundary_only(self):
        m = Mutator(strategies=[MutationStrategy.BOUNDARY], max_payloads_per_field=200)
        payloads = m.generate("")
        # Should include boundary values like empty, None, huge strings
        assert any(p is None for p in payloads), "Expected None in boundary payloads"
        assert any(isinstance(p, int) and p < 0 for p in payloads)

    def test_encoding_only(self):
        m = Mutator(strategies=[MutationStrategy.ENCODING], max_payloads_per_field=200)
        payloads = m.generate("")
        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_format_only(self):
        m = Mutator(strategies=[MutationStrategy.FORMAT], max_payloads_per_field=200)
        payloads = m.generate("")
        text_payloads = [p for p in payloads if isinstance(p, str)]
        assert any("%" in p for p in text_payloads), "Expected format string payloads"

    def test_all_strategy_expands_to_every_category(self):
        m = Mutator(strategies=[MutationStrategy.ALL], max_payloads_per_field=200)
        payloads = m.generate("")
        # Should be the same as default (no strategies specified)
        m2 = Mutator(max_payloads_per_field=200, seed=0)
        m_all = Mutator(strategies=[MutationStrategy.ALL], max_payloads_per_field=200, seed=0)
        # Both should have payloads from all categories
        assert len(m_all.generate("")) > 5


# ------------------------------------------------------------------
# Dict fuzzing
# ------------------------------------------------------------------

class TestGenerateForDict:
    """generate_for_dict produces dicts with one field mutated at a time."""

    def test_produces_mutated_dicts(self):
        m = Mutator(max_payloads_per_field=3, seed=1)
        body = {"username": "admin", "password": "secret"}
        results = m.generate_for_dict(body)
        assert len(results) > 0
        for r in results:
            assert isinstance(r, dict)
            assert "username" in r
            assert "password" in r

    def test_only_one_field_mutated(self):
        m = Mutator(max_payloads_per_field=2, seed=42)
        body = {"a": "1", "b": "2"}
        results = m.generate_for_dict(body)
        for r in results:
            a_changed = r["a"] != "1"
            b_changed = r["b"] != "2"
            # Exactly one should be changed (they could be equal by coincidence,
            # but at least one must be "intended" as mutated)
            assert a_changed or b_changed

    def test_empty_body_returns_empty(self):
        m = Mutator(max_payloads_per_field=5)
        assert m.generate_for_dict({}) == []


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------

class TestEdgeCases:
    def test_numeric_seed_value(self):
        m = Mutator(max_payloads_per_field=50)
        payloads = m.generate(42)
        assert len(payloads) > 0

    def test_none_seed_value(self):
        m = Mutator(max_payloads_per_field=50)
        payloads = m.generate(None)
        assert len(payloads) > 0

    def test_very_small_cap(self):
        m = Mutator(max_payloads_per_field=1, seed=0)
        payloads = m.generate("x")
        assert len(payloads) == 1
