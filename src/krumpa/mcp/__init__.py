"""
GateKrumpa MCP (Model Context Protocol) server.

Exposes GateKrumpa scan, report, import/export, and SDK generation
capabilities as MCP tools that AI agents can invoke.

Built on the official ``mcp`` Python SDK (:class:`FastMCP`).
The server speaks JSON-RPC 2.0 over **stdio** — the standard MCP
transport — and never exposes raw credentials.
"""

from krumpa.mcp.server import create_server
from krumpa.mcp.tools import register_default_tools

__all__ = ["create_server", "register_default_tools"]
