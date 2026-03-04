"""Tests for _module_kwargs — config → module constructor bridge."""

from __future__ import annotations

import pytest

from krumpa.__main__ import _module_kwargs


# ------------------------------------------------------------------
# Basic forwarding
# ------------------------------------------------------------------

class TestModuleKwargsForwarding:
    """Verify that per-module config keys reach module constructors."""

    def test_sneakygits_max_depth(self):
        config = {"sneakygits": {"max_depth": 5}}
        kw = _module_kwargs("sneakygits", config)
        assert kw["max_depth"] == 5

    def test_waaaghlogic_concurrency(self):
        config = {"waaaghlogic": {"concurrency": 10}}
        kw = _module_kwargs("waaaghlogic", config)
        assert kw["concurrency"] == 10

    def test_openkrump_strict_mode_alias(self):
        """YAML uses 'strict_mode' but constructor param is 'strict'."""
        config = {"openkrump": {"strict_mode": True}}
        kw = _module_kwargs("openkrump", config)
        assert kw["strict"] is True

    def test_openkrump_spec_url_from_config(self):
        config = {"openkrump": {"spec_url": "https://api.example.com/spec.yaml"}}
        kw = _module_kwargs("openkrump", config)
        assert kw["spec_url"] == "https://api.example.com/spec.yaml"


# ------------------------------------------------------------------
# CLI overrides
# ------------------------------------------------------------------

class TestCLIOverrides:

    def test_spec_cli_overrides_config(self):
        """CLI --spec flag takes priority over config file spec_url."""
        config = {"openkrump": {"spec_url": "https://old.com/spec"}}
        kw = _module_kwargs("openkrump", config, spec="https://new.com/spec")
        assert kw["spec_url"] == "https://new.com/spec"

    def test_spec_cli_only(self):
        kw = _module_kwargs("openkrump", {}, spec="https://api.com/spec")
        assert kw["spec_url"] == "https://api.com/spec"


# ------------------------------------------------------------------
# Filtering / safety
# ------------------------------------------------------------------

class TestModuleKwargsFiltering:

    def test_unknown_keys_ignored(self):
        """Keys that don't map to constructor params are silently dropped."""
        config = {"sneakygits": {"max_depth": 5, "nonexistent_key": 42}}
        kw = _module_kwargs("sneakygits", config)
        assert "nonexistent_key" not in kw
        assert kw["max_depth"] == 5

    def test_runtime_only_keys_excluded(self):
        """http_client and reporter should never come from config."""
        config = {"grotassault": {"http_client": "INJECTED", "max_payloads_per_field": 50}}
        kw = _module_kwargs("grotassault", config)
        assert "http_client" not in kw
        assert kw["max_payloads_per_field"] == 50

    def test_empty_config_returns_empty(self):
        kw = _module_kwargs("sneakygits", {})
        assert kw == {}

    def test_missing_module_section_returns_empty(self):
        config = {"bosskey": {"min_entropy_bits": 2.0}}
        kw = _module_kwargs("sneakygits", config)
        assert kw == {}

    def test_multiple_valid_keys(self):
        config = {"sneakygits": {"max_depth": 7, "follow_redirects": False}}
        kw = _module_kwargs("sneakygits", config)
        assert kw["max_depth"] == 7
        assert kw["follow_redirects"] is False


# ------------------------------------------------------------------
# All modules can be introspected without error
# ------------------------------------------------------------------

_ALL_MODULES = [
    "sneakygits", "bosskey", "waaaghlogic",
    "grotassault", "redteef", "waaaghgate", "openkrump",
]


class TestModuleKwargsAllModules:

    @pytest.mark.parametrize("name", _ALL_MODULES)
    def test_empty_config_no_error(self, name: str):
        """Every module can be introspected with an empty config."""
        kw = _module_kwargs(name, {})
        assert isinstance(kw, dict)

    @pytest.mark.parametrize("name", _ALL_MODULES)
    def test_garbage_config_ignored(self, name: str):
        """Unknown keys never leak through."""
        config = {name: {"zzz_unknown_key": 999}}
        kw = _module_kwargs(name, config)
        assert "zzz_unknown_key" not in kw
