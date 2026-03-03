"""Tests for krumpa.grotassault.module — GrotAssaultModule orchestrator."""

import json
import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.grotassault.module import GrotAssaultModule
from krumpa.grotassault.fuzzer import FuzzTarget
from krumpa.grotassault.mutator import MutationStrategy


# ------------------------------------------------------------------
# Fake HTTP layer
# ------------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = '{"ok": true}'


class FakeHttpClient:
    def __init__(self, default_status=200, default_text='{"ok": true}'):
        self.default_status = default_status
        self.default_text = default_text
        self.requests: List[Dict[str, Any]] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.requests.append({"method": method, "url": url, "headers": headers, "json_body": json_body})
        return FakeResponse(status_code=self.default_status, text=self.default_text)

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

    async def put(self, url, **kw):
        return await self.request("PUT", url, **kw)

    async def delete(self, url, **kw):
        return await self.request("DELETE", url, **kw)

    async def close(self):
        pass


class _NoopAsync:
    """Stub that returns [] for any method call (sync or async)."""
    def __getattr__(self, name):
        async def _noop(*a, **kw):
            return []
        return _noop


class _NoopBlindOob:
    """Noop for BlindOobDetector — build_payloads is sync, inject_and_poll is async."""
    def build_payloads(self, *a, **kw):
        return []

    async def inject_and_poll(self, *a, **kw):
        return []


def _neutralise_new_components(module: GrotAssaultModule) -> None:
    """Disable Phase 1-4 sub-components so they don't make real requests."""
    noop = _NoopAsync()
    module._xxe_checker = noop
    module._ssrf_checker = noop
    module._nosql_checker = noop
    module._crlf_checker = noop
    module._smuggling_checker = noop
    module._blind_oob = _NoopBlindOob()
    module._deserialization = noop
    module._content_type = noop
    module._path_traversal = noop
    module._open_redirect = noop
    module._ldap_checker = noop
    module._proto_pollution = noop
    module._param_pollution = noop


def _make_module(**kw) -> GrotAssaultModule:
    """Create a GrotAssaultModule with new sub-components neutralised."""
    module = GrotAssaultModule(**kw)
    _neutralise_new_components(module)
    return module


# ------------------------------------------------------------------
# Tests — explicit fuzz targets
# ------------------------------------------------------------------

class TestExplicitFuzzTargets:
    @pytest.mark.asyncio
    async def test_runs_with_explicit_targets(self):
        client = FakeHttpClient()
        ft = FuzzTarget(
            url="https://api.example.com/submit",
            method="POST",
            base_body={"name": "test"},
        )
        module = _make_module(
            fuzz_targets=[ft],
            max_payloads_per_field=3,
            http_client=client,
        )
        ctx = ScanContext(targets=[Target(url="https://api.example.com/submit", method="POST")])
        findings = await module.run(ctx)
        assert isinstance(findings, list)
        # At least baseline + fuzz requests were sent
        assert len(client.requests) >= 2

    @pytest.mark.asyncio
    async def test_findings_propagated_to_module(self):
        client = FakeHttpClient(default_status=500)
        ft = FuzzTarget(
            url="https://api.example.com/crash",
            method="POST",
            base_body={"input": "hello"},
        )
        module = _make_module(
            fuzz_targets=[ft],
            max_payloads_per_field=2,
            http_client=client,
        )
        ctx = ScanContext(targets=[Target(url="https://api.example.com/crash")])
        findings = await module.run(ctx)
        # 500 status should produce findings
        assert len(findings) > 0
        # Module's own findings list is populated
        assert len(module.findings) > 0

    @pytest.mark.asyncio
    async def test_multiple_fuzz_targets(self):
        client = FakeHttpClient()
        ft1 = FuzzTarget(url="https://a.com/x", method="POST", base_body={"q": "1"})
        ft2 = FuzzTarget(url="https://b.com/y", method="POST", base_body={"r": "2"})
        module = _make_module(
            fuzz_targets=[ft1, ft2],
            max_payloads_per_field=2,
            http_client=client,
        )
        ctx = ScanContext()
        await module.run(ctx)
        # Both targets fuzzed → requests to both URLs
        urls = {r["url"] for r in client.requests}
        assert "https://a.com/x" in urls
        assert "https://b.com/y" in urls


# ------------------------------------------------------------------
# Tests — auto-detection from context
# ------------------------------------------------------------------

class TestAutoDetection:
    @pytest.mark.asyncio
    async def test_auto_detects_post_targets_with_json_body(self):
        client = FakeHttpClient()
        module = _make_module(
            max_payloads_per_field=2,
            http_client=client,
        )
        ctx = ScanContext(targets=[
            Target(
                url="https://api.example.com/api/order",
                method="POST",
                body=json.dumps({"item": "widget", "qty": 1}),
            ),
        ])
        findings = await module.run(ctx)
        assert isinstance(findings, list)
        # Should have sent fuzz requests
        assert len(client.requests) >= 2

    @pytest.mark.asyncio
    async def test_auto_detects_body_json_in_metadata(self):
        client = FakeHttpClient()
        module = _make_module(
            max_payloads_per_field=2,
            http_client=client,
        )
        t = Target(url="https://api.example.com/update", method="PUT")
        t.metadata["body_json"] = {"field1": "a", "field2": "b"}
        ctx = ScanContext(targets=[t])
        await module.run(ctx)
        assert len(client.requests) >= 2

    @pytest.mark.asyncio
    async def test_ignores_get_targets(self):
        client = FakeHttpClient()
        module = _make_module(max_payloads_per_field=2, http_client=client)
        ctx = ScanContext(targets=[
            Target(url="https://api.example.com/list", method="GET"),
        ])
        await module.run(ctx)
        # No fuzz requests (GET with no body/query)
        assert len(client.requests) == 0

    @pytest.mark.asyncio
    async def test_auto_detects_query_params(self):
        client = FakeHttpClient()
        module = _make_module(max_payloads_per_field=2, http_client=client)
        ctx = ScanContext(targets=[
            Target(url="https://api.example.com/search?q=test&page=1", method="POST"),
        ])
        await module.run(ctx)
        assert len(client.requests) >= 2


# ------------------------------------------------------------------
# Tests — resolve_target
# ------------------------------------------------------------------

class TestResolveTarget:
    @pytest.mark.asyncio
    async def test_resolves_existing_target(self):
        client = FakeHttpClient()
        original = Target(url="https://api.example.com/endpoint", method="POST",
                          headers={"Authorization": "Bearer xyz"})
        ft = FuzzTarget(url=original.url, method="POST", base_body={"x": "1"})
        module = _make_module(
            fuzz_targets=[ft],
            max_payloads_per_field=1,
            http_client=client,
        )
        ctx = ScanContext(targets=[original])
        await module.run(ctx)
        # Findings should reference the original target
        # (the module looked it up by URL)
        for f in module.findings:
            assert f.target is original or f.target.url == original.url

    @pytest.mark.asyncio
    async def test_synthesises_target_when_missing(self):
        client = FakeHttpClient(default_status=500)
        ft = FuzzTarget(url="https://unknown.com/api", method="POST", base_body={"a": "1"})
        module = _make_module(
            fuzz_targets=[ft],
            max_payloads_per_field=1,
            http_client=client,
        )
        ctx = ScanContext()  # no targets at all
        findings = await module.run(ctx)
        assert len(findings) > 0
        assert findings[0].target.url == "https://unknown.com/api"


# ------------------------------------------------------------------
# Tests — module metadata
# ------------------------------------------------------------------

class TestModuleMetadata:
    def test_name_and_description(self):
        m = _make_module()
        assert m.name == "GrotAssault"
        assert "Mutation" in m.description or "Fuzz" in m.description

    @pytest.mark.asyncio
    async def test_no_targets_returns_empty(self):
        client = FakeHttpClient()
        module = _make_module(http_client=client)
        ctx = ScanContext()
        findings = await module.run(ctx)
        assert findings == []
