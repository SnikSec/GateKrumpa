"""Tests for the SneakyGitsModule orchestrator."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.sneakygits.module import SneakyGitsModule


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class _FakeCrawler:
    """Returns a fixed set of discovered URLs."""

    def __init__(self, discovered: dict[str, list[str]] | None = None, **kw):
        self._discovered = discovered or {}
        self._captured_cookies: dict[str, list[str]] = {}

    async def crawl(self, url: str) -> list[str]:
        return self._discovered.get(url, [])

    @property
    def captured_cookies(self) -> dict[str, list[str]]:
        return dict(self._captured_cookies)


class _FakeFingerprinter:
    """Returns a fixed set of technologies."""

    def __init__(self, techs: dict[str, list[str]] | None = None, **kw):
        self._techs = techs or {}

    async def identify(self, url: str) -> list[str]:
        return self._techs.get(url, [])


class _NoopAsync:
    """Stub that returns [] for any async method call."""
    def __getattr__(self, name):
        async def _noop(*a, **kw):
            return []
        return _noop


def _make_module(
    discovered: dict[str, list[str]] | None = None,
    techs: dict[str, list[str]] | None = None,
) -> SneakyGitsModule:
    """Create a SneakyGitsModule with faked crawler and fingerprinter."""
    mod = SneakyGitsModule()
    mod._crawler = _FakeCrawler(discovered)
    mod._fingerprinter = _FakeFingerprinter(techs)
    # Neutralise sub-components added in Phase 1-4 so they don't make real
    # network calls or produce extra findings.
    mod._header_auditor = _NoopAsync()
    mod._cors_checker = _NoopAsync()
    mod._content_discovery = _NoopAsync()
    mod._js_extractor = _NoopAsync()
    mod._ssl_analyzer = _NoopAsync()
    mod._waf_detector = _NoopAsync()
    mod._backup_scanner = _NoopAsync()
    mod._method_discovery = _NoopAsync()
    mod._info_leakage = _NoopAsync()
    mod._dns_enum = _NoopAsync()
    mod._platform_exposure = _NoopAsync()
    return mod


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestSneakyGitsModule:

    async def test_returns_empty_when_no_targets(self):
        mod = _make_module()
        ctx = ScanContext()
        findings = await mod.run(ctx)
        assert findings == []

    async def test_adds_discovered_urls_as_targets(self):
        mod = _make_module(discovered={
            "https://example.com": ["https://example.com/api", "https://example.com/docs"],
        })
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        await mod.run(ctx)
        urls = [t.url for t in ctx.targets]
        assert "https://example.com/api" in urls
        assert "https://example.com/docs" in urls

    async def test_creates_finding_for_detected_technologies(self):
        mod = _make_module(
            discovered={"https://example.com": []},
            techs={"https://example.com": ["Nginx", "PHP"]},
        )
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        findings = await mod.run(ctx)
        assert len(findings) == 1
        assert "Nginx" in findings[0].description
        assert "PHP" in findings[0].description
        assert findings[0].severity == Severity.INFO
        assert "fingerprint" in findings[0].tags

    async def test_no_finding_when_no_techs_detected(self):
        mod = _make_module(
            discovered={"https://example.com": []},
            techs={"https://example.com": []},
        )
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        findings = await mod.run(ctx)
        assert findings == []

    async def test_multiple_targets(self):
        mod = _make_module(
            discovered={
                "https://a.com": ["https://a.com/x"],
                "https://b.com": [],
            },
            techs={
                "https://a.com": ["React"],
                "https://b.com": ["Django", "Nginx"],
            },
        )
        ctx = ScanContext(targets=[
            Target(url="https://a.com"),
            Target(url="https://b.com"),
        ])
        findings = await mod.run(ctx)
        assert len(findings) == 2

    async def test_findings_registered_on_module(self):
        mod = _make_module(
            discovered={"https://example.com": []},
            techs={"https://example.com": ["Express"]},
        )
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        await mod.run(ctx)
        assert len(mod.findings) == 1
        assert mod.findings[0].module == "SneakyGits"

    async def test_metadata_on_discovered_targets(self):
        mod = _make_module(discovered={
            "https://example.com": ["https://example.com/new"],
        })
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        await mod.run(ctx)
        new_targets = [t for t in ctx.targets if t.url == "https://example.com/new"]
        assert len(new_targets) == 1
        assert new_targets[0].metadata["discovered_by"] == "SneakyGits"

    async def test_default_module_attributes(self):
        mod = SneakyGitsModule()
        assert mod.name == "SneakyGits"
        assert "Recon" in mod.description or "crawl" in mod.description

    async def test_platform_findings_are_included(self):
        mod = _make_module(discovered={"https://example.com": []})

        class _PlatformStub:
            async def analyze(self, target):
                return [Finding(
                    title="Kubernetes API server management surface exposed",
                    description="Publicly reachable Kubernetes endpoints detected",
                    severity=Severity.CRITICAL,
                    target=target,
                    tags=["platform-exposure", "kubernetes"],
                )]

        mod._platform_exposure = _PlatformStub()
        ctx = ScanContext(targets=[Target(url="https://example.com")])
        findings = await mod.run(ctx)

        assert any("platform-exposure" in finding.tags for finding in findings)
