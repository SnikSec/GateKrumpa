"""
GateKrumpa MCP server — built on the official MCP Python SDK.

Uses :class:`mcp.server.fastmcp.FastMCP` so there is **no** hand-rolled
JSON-RPC layer.  The server registers tool functions via ``@mcp.tool()``
and lets the SDK handle transport (stdio by default), protocol
negotiation, and message framing.

Security
--------
* Credentials are resolved via the :mod:`krumpa.core.credentials`
  provider chain — agents never see raw secret values.
* The resolved config dict is stored on the server instance so tools
  can access it at call time.

.. _Model Context Protocol: https://modelcontextprotocol.io/
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("krumpa.mcp")

_SERVER_NAME = "gatekrumpa"
_SERVER_VERSION = "0.1.0"


def create_server(
    *,
    config: Optional[Dict[str, Any]] = None,
) -> FastMCP:
    """Create a :class:`FastMCP` server pre-configured for GateKrumpa.

    Parameters
    ----------
    config:
        Pre-resolved GateKrumpa config dict (credentials already
        interpolated).  Stored as ``server._krumpa_config`` for tool
        handlers to access.

    Returns
    -------
    FastMCP
        Ready-to-use server; call :func:`register_default_tools` next,
        then ``server.run()`` (or ``server.run(transport="stdio")``).
    """
    server = FastMCP(_SERVER_NAME)
    # Stash resolved config so tool handlers can retrieve it.
    server._krumpa_config: Dict[str, Any] = config or {}  # type: ignore[attr-defined]
    logger.info("Created GateKrumpa MCP server (FastMCP)")
    return server
