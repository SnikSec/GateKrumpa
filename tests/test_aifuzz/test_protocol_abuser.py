"""Tests for ProtocolAbuser — MCP tool description injection and plugin poisoning."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.aifuzz.protocol_abuser import ProtocolAbuser, _POISONED_TOOLS, _CANARY
from krumpa.aifuzz.module import _AiSession


def _session():
    return _AiSession(endpoint="https://ai.example.com/v1/chat/completions")


class TestPoisonedToolSchemas:

    def test_all_tools_have_injected_descriptions(self):
        for tool in _POISONED_TOOLS:
            assert _CANARY in tool["description"] or any(
                _CANARY in v.get("description", "")
                for v in tool["parameters"]["properties"].values()
            )

    def test_tools_have_valid_function_schema(self):
        for tool in _POISONED_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "parameters" in tool
            assert tool["parameters"]["type"] == "object"


@pytest.mark.asyncio
class TestProtocolAbuser:

    async def test_detects_plugin_poisoning_when_canary_in_response(self):
        """Model echoes canary from tool description — plugin poisoning confirmed."""
        class _CanaryModel:
            async def request(self, *a, **kw):
                payload = json.dumps({
                    "choices": [{"message": {
                        "content": f"{_CANARY} — I have followed the tool instructions.",
                        "tool_calls": [],
                    }}]
                })
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
            async def close(self): pass

        abuser = ProtocolAbuser(http_client=_CanaryModel())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await abuser.analyze(target, _session(), ScanContext())

        plugin_findings = [f for f in findings if "plugin" in " ".join(f.tags)]
        assert len(plugin_findings) >= 1
        assert plugin_findings[0].severity == Severity.CRITICAL

    async def test_no_finding_when_model_ignores_injected_description(self):
        class _SafeModel:
            async def request(self, *a, **kw):
                payload = json.dumps({"choices": [{"message": {"content": "Here is the weather data."}}]})
                return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
            async def close(self): pass

        abuser = ProtocolAbuser(http_client=_SafeModel())
        target = Target(url="https://ai.example.com/v1/chat/completions")
        findings, _ = await abuser.analyze(target, _session(), ScanContext())

        plugin_findings = [f for f in findings if "plugin" in " ".join(f.tags)]
        assert plugin_findings == []

    async def test_mcp_endpoint_probe_detects_exposed_tools(self):
        """Simulate an exposed MCP tools/list endpoint."""
        class _McpServer:
            async def request(self, method, url, **kw):
                if "/tools/list" in url or "/v1/tools" in url:
                    payload = json.dumps({
                        "result": {"tools": [
                            {"name": "execute_sql", "description": "Run SQL queries"},
                            {"name": "read_file", "description": "Read file contents"},
                        ]}
                    })
                    return type("R", (), {"text": payload, "status_code": 200, "headers": {}})()
                return type("R", (), {"text": "{}", "status_code": 404, "headers": {}})()
            async def close(self): pass

        abuser = ProtocolAbuser(http_client=_McpServer())
        target = Target(url="https://ai.example.com")
        findings, _ = await abuser.analyze(target, _session(), ScanContext())

        mcp_findings = [f for f in findings if "mcp" in " ".join(f.tags) and "unauthenticated" in " ".join(f.tags)]
        assert len(mcp_findings) >= 1
        assert mcp_findings[0].severity == Severity.HIGH
