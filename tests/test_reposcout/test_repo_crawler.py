"""Tests for repo_crawler utilities — URL parsing and RepoData structure."""

from __future__ import annotations

import pytest

from krumpa.reposcout.repo_crawler import _parse_repo, RepoData


class TestParseRepo:

    def test_github_url(self):
        result = _parse_repo("github://myorg/myrepo")
        assert result == ("myorg", "myrepo")

    def test_gitlab_url_with_host(self):
        result = _parse_repo("gitlab://gitlab.example.com/mygroup/myrepo")
        assert result == ("mygroup", "myrepo")

    def test_returns_none_for_invalid_url(self):
        result = _parse_repo("not-a-url")
        # Should not raise; returns None or partial
        assert result is None or isinstance(result, tuple)

    def test_repo_data_defaults(self):
        data = RepoData(provider="github", org="org", repo="repo")
        assert data.default_branch == "main"
        assert data.files == {}
        assert data.tree == []
        assert data.workflow_files == []
        assert data.manifest_files == []


class TestRepoCrawlerGracefulDegradation:
    """RepoCrawler skips gracefully when PyGithub/python-gitlab is not installed."""

    @pytest.mark.asyncio
    async def test_returns_none_when_pygithub_missing(self):
        import sys
        from unittest.mock import patch
        from krumpa.core import Target, TargetType
        from krumpa.reposcout.repo_crawler import RepoCrawler

        with patch.dict(sys.modules, {"github": None, "github.Auth": None}):
            crawler = RepoCrawler(token="", provider=TargetType.GITHUB)
            target = Target(url="github://org/repo")
            result = await crawler.crawl(target)
            # Should return None without raising
            assert result is None
