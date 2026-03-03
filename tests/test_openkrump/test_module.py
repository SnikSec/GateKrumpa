"""Tests for krumpa.openkrump.module — OpenKrumpModule orchestrator."""

import json
import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.openkrump.module import OpenKrumpModule


# ------------------------------------------------------------------
# Fake HTTP layer
# ------------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = '{"id": 1, "name": "Alice"}'


class FakeHttpClient:
    def __init__(self, default_text='{"id": 1, "name": "Alice"}', default_status=200):
        self.default_text = default_text
        self.default_status = default_status
        self.requests: List[Dict[str, Any]] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.requests.append({"method": method, "url": url})
        return FakeResponse(status_code=self.default_status, text=self.default_text)

    async def close(self):
        pass


class _NoopAsync:
    """Stub that returns [] for any async method call."""
    def __getattr__(self, name):
        async def _noop(*a, **kw):
            return []
        return _noop

    def extract_from_spec(self, *a, **kw):
        return {}


def _make_openkrump(**kw) -> OpenKrumpModule:
    """Create an OpenKrumpModule with new sub-components neutralised."""
    mod = OpenKrumpModule(**kw)
    mod._resp_validator = _NoopAsync()
    mod._spec_mass_assign = _NoopAsync()
    # Phase 3 sub-components
    mod._sec_enforcer = _NoopAsync()
    mod._param_tester = _NoopAsync()
    mod._spec_diff = _NoopAsync()
    return mod


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _simple_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "security": [{"bearer": []}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/admin": {
                "post": {
                    "operationId": "adminAction",
                    "responses": {"200": {}},
                    # no security → should be flagged
                },
            },
        },
    }


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestOpenKrumpModule:
    @pytest.mark.asyncio
    async def test_parses_and_adds_targets(self):
        client = FakeHttpClient()
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        await module.run(ctx)
        assert len(ctx.targets) == 2
        urls = {t.url for t in ctx.targets}
        assert "https://api.example.com/users" in urls
        assert "https://api.example.com/admin" in urls

    @pytest.mark.asyncio
    async def test_flags_missing_security(self):
        client = FakeHttpClient()
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        findings = await module.run(ctx)
        security_findings = [f for f in findings if "no_security" in f.tags]
        assert len(security_findings) > 0

    @pytest.mark.asyncio
    async def test_validates_response_schema(self):
        # Return a response that doesn't match the schema
        client = FakeHttpClient(default_text='"not an object"')
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        findings = await module.run(ctx)
        type_findings = [f for f in findings if "type_mismatch" in f.tags]
        assert len(type_findings) > 0

    @pytest.mark.asyncio
    async def test_clean_response_no_schema_issues(self):
        client = FakeHttpClient(default_text='{"id": 1, "name": "Alice"}')
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        findings = await module.run(ctx)
        schema_issues = [f for f in findings if "type_mismatch" in f.tags or "missing_field" in f.tags]
        assert len(schema_issues) == 0

    @pytest.mark.asyncio
    async def test_no_spec_returns_empty(self):
        module = _make_openkrump()
        ctx = ScanContext()
        findings = await module.run(ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_module_metadata(self):
        m = _make_openkrump()
        assert m.name == "OpenKrump"
        assert "API" in m.description

    @pytest.mark.asyncio
    async def test_fetches_spec_from_url(self):
        spec = _simple_spec()
        client = FakeHttpClient(default_text=json.dumps(spec))
        module = _make_openkrump(
            spec_url="https://api.example.com/openapi.json",
            http_client=client,
        )
        ctx = ScanContext()
        await module.run(ctx)
        # First request should fetch the spec
        assert client.requests[0]["url"] == "https://api.example.com/openapi.json"
        # Then endpoints discovered
        assert len(ctx.targets) == 2

    @pytest.mark.asyncio
    async def test_endpoints_stored_on_module(self):
        client = FakeHttpClient()
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        await module.run(ctx)
        assert len(module.endpoints) == 2

    @pytest.mark.asyncio
    async def test_findings_added_to_module(self):
        client = FakeHttpClient()
        module = _make_openkrump(spec=_simple_spec(), http_client=client)
        ctx = ScanContext()
        await module.run(ctx)
        assert len(module.findings) > 0
