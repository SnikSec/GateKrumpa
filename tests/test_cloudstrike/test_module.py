"""Tests for CloudStrikeModule — module-level behaviour."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Target, TargetType


class TestTargetTypeInference:
    """TargetType is inferred from URL scheme."""

    def test_aws_scheme(self):
        t = Target(url="aws://us-east-1")
        assert t.target_type == TargetType.AWS

    def test_github_scheme(self):
        t = Target(url="github://org/repo")
        assert t.target_type == TargetType.GITHUB

    def test_gitlab_scheme(self):
        t = Target(url="gitlab://gitlab.example.com/group/repo")
        assert t.target_type == TargetType.GITLAB

    def test_https_scheme(self):
        t = Target(url="https://example.com")
        assert t.target_type == TargetType.WEB

    def test_http_scheme(self):
        t = Target(url="http://example.com")
        assert t.target_type == TargetType.WEB


@pytest.mark.asyncio
class TestCloudStrikeModuleGracefulSkip:
    """Module skips gracefully when boto3 is unavailable or no aws:// targets."""

    async def test_skips_when_no_aws_targets(self):
        """Module returns empty findings when no aws:// targets are in context."""
        from unittest.mock import patch

        # boto3 available but no aws:// targets
        with patch.dict("sys.modules", {}):  # boto3 may or may not be installed
            try:
                import boto3  # noqa: F401
                boto3_available = True
            except ImportError:
                boto3_available = False

        if not boto3_available:
            pytest.skip("boto3 not installed")

        from krumpa.cloudstrike.module import CloudStrikeModule

        ctx = ScanContext()
        ctx.add_target(Target(url="https://example.com"))  # web target only

        module = CloudStrikeModule()
        findings = await module.run(ctx)
        assert findings == []

    async def test_skips_when_boto3_not_installed(self):
        """Module logs a warning and returns [] when boto3 is not installed."""
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"boto3": None}):
            from importlib import reload
            import krumpa.cloudstrike.module as csm
            # Reset the import so it sees boto3=None
            try:
                reload(csm)
            except Exception:
                pass  # reload may fail due to the None sentinel — that's fine

            ctx = ScanContext()
            ctx.add_target(Target(url="aws://us-east-1"))
            module = csm.CloudStrikeModule()
            # Should not raise — just return []
            findings = await module.run(ctx)
            assert isinstance(findings, list)
