"""Tests for krumpa.mcp — FastMCP server creation and tool registration."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp.server.fastmcp import FastMCP

from krumpa.mcp.server import create_server, _SERVER_NAME
from krumpa.mcp.tools import (
    register_default_tools,
    _list_modules_handler,
    _module_info_handler,
    _report_handler,
    _import_handler,
    _export_handler,
)


# ===================================================================
# create_server
# ===================================================================

class TestCreateServer:
    """create_server returns a properly configured FastMCP instance."""

    def test_returns_fastmcp(self) -> None:
        server = create_server()
        assert isinstance(server, FastMCP)

    def test_server_name(self) -> None:
        server = create_server()
        assert server.name == _SERVER_NAME

    def test_config_stored(self) -> None:
        cfg = {"http": {"timeout": 30}}
        server = create_server(config=cfg)
        assert server._krumpa_config == cfg  # pyright: ignore[reportAttributeAccessIssue]

    def test_empty_config_default(self) -> None:
        server = create_server()
        assert server._krumpa_config == {}  # pyright: ignore[reportAttributeAccessIssue]

    def test_config_none(self) -> None:
        server = create_server(config=None)
        assert server._krumpa_config == {}  # pyright: ignore[reportAttributeAccessIssue]

    def test_version_set(self) -> None:
        server = create_server()
        assert server._mcp_server.name == _SERVER_NAME  # pyright: ignore[reportAttributeAccessIssue]


# ===================================================================
# Tool registration via FastMCP
# ===================================================================

class TestToolRegistration:
    """register_default_tools adds all expected tools to a FastMCP server."""

    def _registered_names(self, server: FastMCP) -> set[str]:
        """Extract tool names from the FastMCP server's internal registry."""
        # FastMCP stores tools in _tool_manager._tools dict
        manager = server._tool_manager  # pyright: ignore[reportAttributeAccessIssue]
        return set(manager._tools.keys())  # pyright: ignore[reportAttributeAccessIssue]

    def test_default_tools_registered(self) -> None:
        server = create_server()
        register_default_tools(server)
        names = self._registered_names(server)

        expected = {
            "gatekrumpa_scan",
            "gatekrumpa_list_modules",
            "gatekrumpa_module_info",
            "gatekrumpa_report",
            "gatekrumpa_import",
            "gatekrumpa_export",
            "gatekrumpa_generate_sdk",
        }
        assert names == expected

    def test_all_seven_tools(self) -> None:
        server = create_server()
        register_default_tools(server)
        names = self._registered_names(server)
        assert len(names) == 7

    def test_config_passed_to_server(self) -> None:
        config = {"http": {"timeout": 99}}
        server = create_server(config=config)
        register_default_tools(server, config)
        assert server._krumpa_config == config  # pyright: ignore[reportAttributeAccessIssue]

    def test_register_idempotent(self) -> None:
        """Calling register_default_tools twice doesn't duplicate."""
        server = create_server()
        register_default_tools(server)
        register_default_tools(server)
        names = self._registered_names(server)
        # FastMCP overwrites tools with same name
        assert len(names) == 7

    def test_custom_tool_alongside(self) -> None:
        """Custom user-defined tools coexist with defaults."""
        server = create_server()
        register_default_tools(server)

        @server.tool(name="custom_tool")
        def custom() -> str:
            """A custom tool."""
            return "custom"

        names = self._registered_names(server)
        assert "custom_tool" in names
        assert len(names) == 8


# ===================================================================
# Handler: list_modules
# ===================================================================

class TestListModulesHandler:
    """_list_modules_handler returns module info."""

    @pytest.mark.asyncio
    async def test_lists_modules(self) -> None:
        result = await _list_modules_handler()
        assert "modules" in result
        assert len(result["modules"]) > 0

    @pytest.mark.asyncio
    async def test_known_modules_present(self) -> None:
        result = await _list_modules_handler()
        names = [m["name"] for m in result["modules"]]
        assert "sneakygits" in names
        assert "bosskey" in names
        assert "grotassault" in names

    @pytest.mark.asyncio
    async def test_module_has_keys(self) -> None:
        result = await _list_modules_handler()
        m = result["modules"][0]
        assert "name" in m
        assert "class" in m
        assert "description" in m


# ===================================================================
# Handler: module_info
# ===================================================================

class TestModuleInfoHandler:
    """_module_info_handler returns module details."""

    @pytest.mark.asyncio
    async def test_valid_module(self) -> None:
        result = await _module_info_handler("sneakygits")
        assert "name" in result
        assert "description" in result
        assert "class" in result

    @pytest.mark.asyncio
    async def test_empty_name(self) -> None:
        result = await _module_info_handler("")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_whitespace_name(self) -> None:
        result = await _module_info_handler("   ")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_unknown_module(self) -> None:
        result = await _module_info_handler("nonexistent_module")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_case_insensitive(self) -> None:
        result = await _module_info_handler("BOSSKEY")
        assert "name" in result
        assert "error" not in result


# ===================================================================
# Handler: report
# ===================================================================

class TestReportHandler:
    """_report_handler converts scan results."""

    @pytest.mark.asyncio
    async def test_missing_input(self) -> None:
        result = await _report_handler("", "json")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_file_not_found(self) -> None:
        result = await _report_handler("/nonexistent/file.json", "json")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_unknown_format(self, tmp_path: Any) -> None:
        f = tmp_path / "scan.json"
        f.write_text(json.dumps({"scan_id": "t", "findings": []}))
        result = await _report_handler(str(f), "pdf")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_valid_report_markdown(self, tmp_path: Any) -> None:
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

        result = await _report_handler(str(f), "markdown")
        assert result["format"] == "markdown"
        assert "XSS" in result["content"]

    @pytest.mark.asyncio
    async def test_valid_report_json(self, tmp_path: Any) -> None:
        scan_data = {"scan_id": "test456", "findings": []}
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(scan_data))

        result = await _report_handler(str(f), "json")
        assert result["format"] == "json"

    @pytest.mark.asyncio
    async def test_valid_report_sarif(self, tmp_path: Any) -> None:
        scan_data = {"scan_id": "sarif-test", "findings": []}
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(scan_data))

        result = await _report_handler(str(f), "sarif")
        assert result["format"] == "sarif"

    @pytest.mark.asyncio
    async def test_valid_report_html(self, tmp_path: Any) -> None:
        scan_data = {"scan_id": "html-test", "findings": []}
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(scan_data))

        result = await _report_handler(str(f), "html")
        assert result["format"] == "html"

    @pytest.mark.asyncio
    async def test_valid_report_junit(self, tmp_path: Any) -> None:
        scan_data = {"scan_id": "junit-test", "findings": []}
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(scan_data))

        result = await _report_handler(str(f), "junit")
        assert result["format"] == "junit"


# ===================================================================
# Handler: import
# ===================================================================

class TestImportHandler:
    """_import_handler imports from external formats."""

    @pytest.mark.asyncio
    async def test_missing_path(self) -> None:
        result = await _import_handler("", "har")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_missing_format(self) -> None:
        result = await _import_handler("/some/file", "")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_file_not_found(self) -> None:
        result = await _import_handler("/nonexistent/file.har", "har")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_unknown_format(self, tmp_path: Any) -> None:
        f = tmp_path / "data.txt"
        f.write_text("{}")
        result = await _import_handler(str(f), "unknown")
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

        result = await _import_handler(str(f), "har")
        assert result["imported_targets"] > 0
        assert "targets" in result


# ===================================================================
# Handler: export
# ===================================================================

class TestExportHandler:
    """_export_handler exports to HAR."""

    @pytest.mark.asyncio
    async def test_missing_path(self) -> None:
        result = await _export_handler("")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_file_not_found(self) -> None:
        result = await _export_handler("/nonexistent/file.json")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_valid_export(self, tmp_path: Any) -> None:
        data = {
            "records": [
                {
                    "method": "GET",
                    "url": "http://example.com",
                    "status_code": 200,
                    "request_headers": {},
                    "response_headers": {},
                    "duration_ms": 50,
                    "response_body_preview": "ok",
                }
            ]
        }
        f = tmp_path / "scan.json"
        f.write_text(json.dumps(data))

        result = await _export_handler(str(f))
        assert result["format"] == "har"
        assert result["records_exported"] == 1

    @pytest.mark.asyncio
    async def test_empty_records(self, tmp_path: Any) -> None:
        data = {"records": []}
        f = tmp_path / "empty.json"
        f.write_text(json.dumps(data))

        result = await _export_handler(str(f))
        assert result["records_exported"] == 0


# ===================================================================
# FastMCP integration — tool callable via SDK
# ===================================================================

class TestFastMCPToolSchema:
    """Tools registered on FastMCP have correct schema metadata."""

    def _get_tools(self, server: FastMCP) -> dict[str, Any]:
        manager = server._tool_manager  # pyright: ignore[reportAttributeAccessIssue]
        return dict(manager._tools)  # pyright: ignore[reportAttributeAccessIssue]

    def test_scan_tool_has_targets_param(self) -> None:
        server = create_server()
        register_default_tools(server)
        tools = self._get_tools(server)
        scan = tools["gatekrumpa_scan"]
        # FastMCP Tool has parameters attribute with schema info
        schema = scan.parameters
        assert "targets" in schema.get("properties", {}) or any(
            p.get("name") == "targets"
            for p in schema.get("properties", {}).values()
        ) or "targets" in str(schema)

    def test_report_tool_has_format_param(self) -> None:
        server = create_server()
        register_default_tools(server)
        tools = self._get_tools(server)
        report_tool = tools["gatekrumpa_report"]
        schema = report_tool.parameters
        assert "format" in str(schema)

    def test_module_info_has_description(self) -> None:
        server = create_server()
        register_default_tools(server)
        tools = self._get_tools(server)
        info_tool = tools["gatekrumpa_module_info"]
        assert info_tool.description
        assert "module" in info_tool.description.lower()

    def test_all_tools_have_descriptions(self) -> None:
        server = create_server()
        register_default_tools(server)
        tools = self._get_tools(server)
        for name, tool in tools.items():
            assert tool.description, f"{name} missing description"
