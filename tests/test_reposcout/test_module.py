"""Tests for RepoScoutModule — module-level target routing."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Target, TargetType


@pytest.mark.asyncio
class TestRepoScoutModuleRouting:

    async def test_skips_when_no_repo_targets(self):
        from krumpa.reposcout.module import RepoScoutModule
        module = RepoScoutModule()
        ctx = ScanContext()
        ctx.add_target(Target(url="https://plain-web.example.com"))
        findings = await module.run(ctx)
        assert findings == []

    async def test_skips_empty_context(self):
        from krumpa.reposcout.module import RepoScoutModule
        module = RepoScoutModule()
        ctx = ScanContext()
        findings = await module.run(ctx)
        assert findings == []

    async def test_github_target_type(self):
        t = Target(url="github://org/repo")
        assert t.target_type == TargetType.GITHUB

    async def test_gitlab_target_type(self):
        t = Target(url="gitlab://gitlab.example.com/group/repo")
        assert t.target_type == TargetType.GITLAB

    async def test_module_has_no_dependencies(self):
        from krumpa.reposcout.module import RepoScoutModule
        assert RepoScoutModule.dependencies == []
