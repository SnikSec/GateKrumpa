"""Tests for krumpa.mcp — MCP server and tool registration."""

from __future__ import annotations

import json
from io import StringIO
from typing import Any

import pytest

from krumpa.mcp.server import (
    McpServer,
    ToolDefinition,
    ToolParameter,
    _write_message,
)
from krumpa.mcp.tools import register_default_tools


# ===================================================================
# ToolDefinition
# ===================================================================

class TestToolDefinition:
    """ToolDefinition produces correct JSON Schema."""

    def test_empty_params(self) -> None:
        td = ToolDefinition(name="test_tool", description="A test")
        schema = td.input_schema()
        assert schema == {"type": "object", "properties": {}}

    def test_required_param(self) -> None:
        td = ToolDefinition(
            name="tool",
            description="desc",
            parameters=[
                ToolParameter(name="url", type="string", required=True, description="Target URL"),
            ],
        )
        schema = td.input_schema()
        assert "url" in schema["properties"]
        assert schema["required"] == ["url"]

    def test_optional_with_default(self) -> None:
        td = ToolDefinition(
            name="tool",
            description="desc",
            parameters=[
                ToolParameter(name="fmt", type="string", default="json", description="Format"),
            ],
        )
        schema = td.input_schema()
        assert schema["properties"]["fmt"]["default"] == "json"
        assert "required" not in schema

    def test_enum_param(self) -> None:
        td = ToolDefinition(
            name="tool",
            description="desc",
            parameters=[
                ToolParameter(name="fmt", type="string", enum=["json", "sarif"]),
            ],
        )
        schema = td.input_schema()
        assert schema["properties"]["fmt"]["enum"] == ["json", "sarif"]


# ===================================================================
# McpServer — protocol handling
# ===================================================================

class TestMcpServerProtocol:
    """McpServer handles JSON-RPC messages correctly."""

    def _server(self) -> McpServer:
        return McpServer(config={"test": True})

    @pytest.mark.asyncio
    async def test_initialize(self) -> None:
        server = self._server()
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        resp = await server.handle_message(msg)
        assert resp is not None
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "gatekrumpa"

    @pytest.mark.asyncio
    async def test_ping(self) -> None:
        server = self._server()
        msg = {"jsonrpc": "2.0", "id": 42, "method": "ping", "params": {}}
        resp = await server.handle_message(msg)
        assert resp is not None
        assert resp["id"] == 42
        assert resp["result"] == {}

    @pytest.mark.asyncio
    async def test_tools_list_empty(self) -> None:
        server = self._server()
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        resp = await server.handle_message(msg)
        assert resp is not None
        assert resp["result"]["tools"] == []

    @pytest.mark.asyncio
    async def test_tools_list_with_registered(self) -> None:
        server = self._server()
        server.register_tool(ToolDefinition(
            name="my_tool",
            description="My test tool",
            parameters=[ToolParameter(name="x", type="string", required=True)],
        ))
        msg = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        resp = await server.handle_message(msg)
        assert resp is not None
        tools = resp["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "my_tool"
        assert "x" in tools[0]["inputSchema"]["properties"]

    @pytest.mark.asyncio
    async def test_tools_call_success(self) -> None:
        server = self._server()

        async def _handler(args: dict, **kw: Any) -> dict:
            return {"echo": args.get("msg", "")}

        server.register_tool(ToolDefinition(
            name="echo",
            description="Echo tool",
            parameters=[ToolParameter(name="msg", type="string")],
            handler=_handler,
        ))

        msg = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"msg": "hello"}},
        }
        resp = await server.handle_message(msg)
        assert resp is not None
        content = resp["result"]["content"]
        assert len(content) == 1
        parsed = json.loads(content[0]["text"])
        assert parsed["echo"] == "hello"

    @pytest.mark.asyncio
    async def test_tools_call_unknown(self) -> None:
        server = self._server()
        msg = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        }
        resp = await server.handle_message(msg)
        assert resp is not None
        assert "error" in resp

    @pytest.mark.asyncio
    async def test_tools_call_handler_error(self) -> None:
        server = self._server()

        async def _bad_handler(args: dict, **kw: Any) -> dict:
            raise ValueError("boom")

        server.register_tool(ToolDefinition(
            name="bad",
            description="Fails",
            handler=_bad_handler,
        ))

        msg = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "bad", "arguments": {}},
        }
        resp = await server.handle_message(msg)
        assert resp is not None
        assert resp["result"]["isError"] is True
        assert "boom" in resp["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_unknown_method(self) -> None:
        server = self._server()
        msg = {"jsonrpc": "2.0", "id": 7, "method": "unknown/method", "params": {}}
        resp = await server.handle_message(msg)
        assert resp is not None
        assert resp["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_notification_no_response(self) -> None:
        server = self._server()
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        resp = await server.handle_message(msg)
        assert resp is None

    @pytest.mark.asyncio
    async def test_cancelled_notification(self) -> None:
        server = self._server()
        msg = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "abc"},
        }
        resp = await server.handle_message(msg)
        assert resp is None


# ===================================================================
# McpServer — stdio transport
# ===================================================================

class TestMcpServerStdio:
    """McpServer.run() reads from stdin and writes to stdout."""

    @pytest.mark.asyncio
    async def test_run_initialize_ping(self) -> None:
        server = McpServer()

        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "test"}},
        })
        ping_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
            "params": {},
        })

        input_stream = StringIO(init_msg + "\n" + ping_msg + "\n")
        output_stream = StringIO()

        await server.run(input_stream=input_stream, output_stream=output_stream)

        output_stream.seek(0)
        lines = output_stream.read().strip().split("\n")
        assert len(lines) == 2

        resp1 = json.loads(lines[0])
        assert resp1["id"] == 1
        assert "serverInfo" in resp1["result"]

        resp2 = json.loads(lines[1])
        assert resp2["id"] == 2
        assert resp2["result"] == {}

    @pytest.mark.asyncio
    async def test_run_invalid_json(self) -> None:
        server = McpServer()
        input_stream = StringIO("not valid json\n")
        output_stream = StringIO()

        await server.run(input_stream=input_stream, output_stream=output_stream)

        output_stream.seek(0)
        lines = output_stream.read().strip().split("\n")
        assert len(lines) == 1
        resp = json.loads(lines[0])
        assert resp["error"]["code"] == -32700

    @pytest.mark.asyncio
    async def test_run_empty_lines_skipped(self) -> None:
        server = McpServer()
        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
        input_stream = StringIO("\n\n" + ping + "\n\n")
        output_stream = StringIO()

        await server.run(input_stream=input_stream, output_stream=output_stream)

        output_stream.seek(0)
        lines = [l for l in output_stream.read().strip().split("\n") if l]
        assert len(lines) == 1

    @pytest.mark.asyncio
    async def test_run_batch_request(self) -> None:
        server = McpServer()
        batch = json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
        ])
        input_stream = StringIO(batch + "\n")
        output_stream = StringIO()

        await server.run(input_stream=input_stream, output_stream=output_stream)

        output_stream.seek(0)
        lines = output_stream.read().strip().split("\n")
        assert len(lines) == 1
        responses = json.loads(lines[0])
        assert isinstance(responses, list)
        assert len(responses) == 2


# ===================================================================
# Tool registration
# ===================================================================

class TestToolRegistration:
    """register_default_tools adds all expected tools."""

    def test_default_tools_registered(self) -> None:
        server = McpServer()
        register_default_tools(server)
        tools = server.tools

        expected = {
            "gatekrumpa_scan",
            "gatekrumpa_list_modules",
            "gatekrumpa_module_info",
            "gatekrumpa_report",
            "gatekrumpa_import",
            "gatekrumpa_export",
            "gatekrumpa_generate_sdk",
        }
        assert set(tools.keys()) == expected

    def test_all_tools_have_handlers(self) -> None:
        server = McpServer()
        register_default_tools(server)
        for name, td in server.tools.items():
            assert td.handler is not None, f"{name} has no handler"

    def test_all_tools_have_descriptions(self) -> None:
        server = McpServer()
        register_default_tools(server)
        for name, td in server.tools.items():
            assert td.description, f"{name} has no description"

    def test_scan_tool_has_targets_param(self) -> None:
        server = McpServer()
        register_default_tools(server)
        scan = server.tools["gatekrumpa_scan"]
        param_names = [p.name for p in scan.parameters]
        assert "targets" in param_names

    def test_config_passed_to_scan(self) -> None:
        config = {"http": {"timeout": 99}}
        server = McpServer(config=config)
        register_default_tools(server, config)
        assert server._config == config  # pyright: ignore[reportPrivateUsage]


# ===================================================================
# Tool decorator
# ===================================================================

class TestToolDecorator:
    """McpServer.tool() decorator registers functions."""

    def test_decorator_registration(self) -> None:
        server = McpServer()

        @server.tool(
            "my_tool",
            description="My tool",
            parameters=[ToolParameter(name="x", type="string")],
        )
        async def my_tool(args: dict, **kw: Any) -> dict:
            return {"x": args["x"]}

        assert "my_tool" in server.tools
        assert server.tools["my_tool"].handler is my_tool


# ===================================================================
# Tool handlers — list_modules
# ===================================================================

class TestListModulesTool:
    """gatekrumpa_list_modules returns module info."""

    @pytest.mark.asyncio
    async def test_lists_modules(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_list_modules"]
        assert td.handler is not None

        result = await td.handler({})
        assert "modules" in result
        assert len(result["modules"]) > 0
        module_names = [m["name"] for m in result["modules"]]
        assert "sneakygits" in module_names
        assert "bosskey" in module_names


# ===================================================================
# Tool handlers — module_info
# ===================================================================

class TestModuleInfoTool:
    """gatekrumpa_module_info returns module details."""

    @pytest.mark.asyncio
    async def test_valid_module(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_module_info"]
        assert td.handler is not None

        result = await td.handler({"module_name": "sneakygits"})
        assert "name" in result
        assert "description" in result

    @pytest.mark.asyncio
    async def test_missing_name(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_module_info"]
        assert td.handler is not None

        result = await td.handler({})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_unknown_module(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_module_info"]
        assert td.handler is not None

        result = await td.handler({"module_name": "nonexistent_module"})
        assert "error" in result


# ===================================================================
# Tool handlers — report
# ===================================================================

class TestReportTool:
    """gatekrumpa_report converts scan results."""

    @pytest.mark.asyncio
    async def test_missing_input(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_report"]
        assert td.handler is not None

        result = await td.handler({})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_file_not_found(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_report"]
        assert td.handler is not None

        result = await td.handler({"input_path": "/nonexistent/file.json", "format": "json"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_valid_report(self, tmp_path: Any) -> None:
        scan_data = {
            "scan_id": "test123",
            "findings": [
                {
                    "id": "f1",
                    "title": "XSS",
                    "description": "Reflected XSS",
                    "severity": "high",
                    "module": "grotassault",
                    "target": "http://example.com",
                    "evidence": "<script>",
                    "remediation": "Escape output",
                }
            ],
        }
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(scan_data))

        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_report"]
        assert td.handler is not None

        result = await td.handler({"input_path": str(f), "format": "markdown"})
        assert result["format"] == "markdown"
        assert "XSS" in result["content"]


# ===================================================================
# Tool handlers — import
# ===================================================================

class TestImportTool:
    """gatekrumpa_import imports from external formats."""

    @pytest.mark.asyncio
    async def test_missing_path(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_import"]
        assert td.handler is not None
        result = await td.handler({})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_missing_format(self) -> None:
        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_import"]
        assert td.handler is not None
        result = await td.handler({"input_path": "/some/file"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_har_import(self, tmp_path: Any) -> None:
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/api",
                            "headers": [],
                            "queryString": [],
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "content": {"text": "ok"},
                        },
                        "time": 100,
                    }
                ]
            }
        }
        f = tmp_path / "traffic.har"
        f.write_text(json.dumps(har))

        server = McpServer()
        register_default_tools(server)
        td = server.tools["gatekrumpa_import"]
        assert td.handler is not None

        result = await td.handler({"input_path": str(f), "format": "har"})
        assert result["imported_targets"] > 0


# ===================================================================
# _write_message
# ===================================================================

class TestWriteMessage:
    """_write_message writes newline-terminated compact JSON."""

    def test_writes_json_line(self) -> None:
        out = StringIO()
        _write_message(out, {"jsonrpc": "2.0", "id": 1, "result": {}})
        out.seek(0)
        line = out.read()
        assert line.endswith("\n")
        parsed = json.loads(line)
        assert parsed["id"] == 1

    def test_compact_format(self) -> None:
        out = StringIO()
        _write_message(out, {"a": "b"})
        out.seek(0)
        text = out.read().strip()
        # Compact: no spaces after : or ,
        assert text == '{"a":"b"}'
