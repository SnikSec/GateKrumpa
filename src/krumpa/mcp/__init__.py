"""
GateKrumpa MCP (Model Context Protocol) server.

Exposes GateKrumpa scan, report, import/export, and SDK generation
capabilities as MCP tools that AI agents can invoke.

The server speaks JSON-RPC 2.0 over **stdio** — the standard MCP
transport — and never exposes raw credentials.  All secret resolution
happens through the credential provider chain.
"""

from krumpa.mcp.server import McpServer
from krumpa.mcp.tools import register_default_tools

__all__ = ["McpServer", "register_default_tools"]
