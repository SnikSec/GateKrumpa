"""Tests for multi-target collection — _collect_targets helper."""

from __future__ import annotations

import click
import pytest

from krumpa.__main__ import _collect_targets  # pyright: ignore[reportPrivateUsage]


# ------------------------------------------------------------------
# CLI targets (positional tuple)
# ------------------------------------------------------------------

class TestCliTargets:

    def test_single_target(self):
        result = _collect_targets(("https://example.com",), None, {})
        assert len(result) == 1
        assert result[0].url == "https://example.com"

    def test_multiple_targets(self):
        result = _collect_targets(
            ("https://a.com", "https://b.com", "https://c.com"),
            None, {},
        )
        assert len(result) == 3

    def test_strips_whitespace(self):
        result = _collect_targets(("  https://example.com  ",), None, {})
        assert result[0].url == "https://example.com"

    def test_empty_tuple(self):
        result = _collect_targets((), None, {})
        assert result == []

    def test_default_method_is_get(self):
        result = _collect_targets(("https://example.com",), None, {})
        assert result[0].method == "GET"


# ------------------------------------------------------------------
# Targets file
# ------------------------------------------------------------------

class TestTargetsFile:

    def test_reads_urls_from_file(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("https://a.com\nhttps://b.com\nhttps://c.com\n")
        result = _collect_targets((), str(f), {})
        assert len(result) == 3

    def test_ignores_comments(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("# This is a comment\nhttps://a.com\n# Another\nhttps://b.com\n")
        result = _collect_targets((), str(f), {})
        assert len(result) == 2

    def test_ignores_blank_lines(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("https://a.com\n\n\nhttps://b.com\n\n")
        result = _collect_targets((), str(f), {})
        assert len(result) == 2

    def test_nonexistent_file_raises(self):
        with pytest.raises(click.BadParameter, match="not found"):
            _collect_targets((), "/nonexistent/targets.txt", {})

    def test_none_file_is_noop(self):
        result = _collect_targets(("https://a.com",), None, {})
        assert len(result) == 1


# ------------------------------------------------------------------
# Config campaign.targets
# ------------------------------------------------------------------

class TestConfigTargets:

    def test_string_entries(self):
        config = {
            "campaign": {
                "targets": ["https://a.com", "https://b.com"],
            }
        }
        result = _collect_targets((), None, config)
        assert len(result) == 2

    def test_dict_entries(self):
        config = {
            "campaign": {
                "targets": [
                    {
                        "url": "https://example.com/api",
                        "method": "POST",
                        "headers": {"Authorization": "Bearer tok"},
                        "body": '{"key": "val"}',
                        "metadata": {"env": "staging"},
                    }
                ],
            }
        }
        result = _collect_targets((), None, config)
        assert len(result) == 1
        t = result[0]
        assert t.url == "https://example.com/api"
        assert t.method == "POST"
        assert t.headers["Authorization"] == "Bearer tok"
        assert t.body == '{"key": "val"}'
        assert t.metadata["env"] == "staging"

    def test_mixed_string_and_dict(self):
        config = {
            "campaign": {
                "targets": [
                    "https://a.com",
                    {"url": "https://b.com", "method": "PUT"},
                ],
            }
        }
        result = _collect_targets((), None, config)
        assert len(result) == 2
        assert result[0].method == "GET"
        assert result[1].method == "PUT"

    def test_empty_config(self):
        result = _collect_targets((), None, {})
        assert result == []

    def test_no_campaign_key(self):
        result = _collect_targets((), None, {"scan": {"modules": ["sneakygits"]}})
        assert result == []

    def test_dict_missing_url_skipped(self):
        config = {
            "campaign": {
                "targets": [{"method": "POST"}],  # no url
            }
        }
        result = _collect_targets((), None, config)
        assert result == []


# ------------------------------------------------------------------
# Deduplication
# ------------------------------------------------------------------

class TestDeduplication:

    def test_same_url_deduplicated(self):
        result = _collect_targets(
            ("https://example.com", "https://example.com"),
            None, {},
        )
        assert len(result) == 1

    def test_different_methods_not_deduplicated(self):
        config = {
            "campaign": {
                "targets": [
                    "https://example.com",
                    {"url": "https://example.com", "method": "POST"},
                ],
            }
        }
        result = _collect_targets((), None, config)
        assert len(result) == 2

    def test_dedup_across_sources(self, tmp_path):
        """CLI target + same URL in file → deduplicated."""
        f = tmp_path / "targets.txt"
        f.write_text("https://example.com\n")
        result = _collect_targets(("https://example.com",), str(f), {})
        assert len(result) == 1

    def test_dedup_across_all_three_sources(self, tmp_path):
        """CLI + file + config all with the same URL → 1 target."""
        f = tmp_path / "targets.txt"
        f.write_text("https://example.com\n")
        config = {"campaign": {"targets": ["https://example.com"]}}
        result = _collect_targets(("https://example.com",), str(f), config)
        assert len(result) == 1


# ------------------------------------------------------------------
# Merge ordering
# ------------------------------------------------------------------

class TestMergeOrder:

    def test_cli_targets_first(self, tmp_path):
        """CLI targets appear before file targets."""
        f = tmp_path / "targets.txt"
        f.write_text("https://file.com\n")
        config = {"campaign": {"targets": ["https://config.com"]}}
        result = _collect_targets(("https://cli.com",), str(f), config)
        urls = [t.url for t in result]
        assert urls == ["https://cli.com", "https://file.com", "https://config.com"]
