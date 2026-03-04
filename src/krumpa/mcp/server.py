"""
GateKrumpa MCP server — JSON-RPC 2.0 over stdio.

Implements the `Model Context Protocol`_ server-side transport with
zero external dependencies beyond the Python stdlib.  The server:

* Reads newline-delimited JSON-RPC messages from **stdin**
* Writes newline-delimited JSON-RPC responses to **stdout**
* Handles ``initialize``, ``tools/list``, ``tools/call``,
  ``notifications/initialized``, and ``ping``

Security
--------
* Credentials are resolved via the :mod:`krumpa.core.credentials`
  provider chain — agents never see raw secret values.
* All mutable operations produce structured results so the caller
  can decide what to surface.

.. _Model Context Protocol: https://modelcontextprotocol.io/
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("krumpa.mcp")

# MCP protocol version and server metadata
_MCP_PROTOCOL_VERSION = "2024-11-05"
_SERVER_NAME = "gatekrumpa"
_SERVER_VERSION = "0.1.0"


# ===================================================================
# Data types
# ===================================================================

@dataclass
class ToolParameter:
    """A single parameter for an MCP tool."""
    name: str
    description: str = ""
    type: str = "string"
    required: bool = False
    enum: Optional[List[str]] = None
    default: Any = None


@dataclass
class ToolDefinition:
    """Declarative description of an MCP tool."""
    name: str
    description: str
    parameters: List[ToolParameter] = field(default_factory=list)
    handler: Optional[Callable[..., Coroutine[Any, Any, Any]]] = field(
        default=None, repr=False,
    )

    def input_schema(self) -> Dict[str, Any]:
        """Return JSON Schema for the tool's input parameters."""
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for p in self.parameters:
            prop: Dict[str, Any] = {"type": p.type, "description": p.description}
            if p.enum:
                prop["enum"] = p.enum
            if p.default is not None:
                prop["default"] = p.default
            properties[p.name] = prop
            if p.required:
                required.append(p.name)
        schema: Dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema


# ===================================================================
# MCP Server
# ===================================================================

class McpServer:
    """MCP server running over stdio (stdin/stdout).

    Usage::

        server = McpServer()
        register_default_tools(server, config)
        await server.run()

    Parameters
    ----------
    config:
        Pre-resolved GateKrumpa config dict (credentials already
        interpolated).  Passed to tool handlers as context.
    """

    def __init__(self, *, config: Optional[Dict[str, Any]] = None) -> None:
        self._tools: Dict[str, ToolDefinition] = {}
        self._config: Dict[str, Any] = config or {}
        self._initialized = False

    # -- tool registration -------------------------------------------------

    def register_tool(self, tool: ToolDefinition) -> None:
        """Register an MCP tool definition."""
        self._tools[tool.name] = tool
        logger.info("Registered MCP tool: %s", tool.name)

    def tool(
        self,
        name: str,
        *,
        description: str = "",
        parameters: Optional[List[ToolParameter]] = None,
    ) -> Callable:
        """Decorator to register an async function as an MCP tool."""
        def decorator(fn: Callable[..., Coroutine[Any, Any, Any]]) -> Callable:
            td = ToolDefinition(
                name=name,
                description=description or fn.__doc__ or "",
                parameters=parameters or [],
                handler=fn,
            )
            self.register_tool(td)
            return fn
        return decorator

    @property
    def tools(self) -> Dict[str, ToolDefinition]:
        """Return the registered tool definitions."""
        return dict(self._tools)

    # -- protocol handlers -------------------------------------------------

    async def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatch a single JSON-RPC message and return the response.

        Returns ``None`` for notifications (no ``id`` field).
        """
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        # Notifications (no id) — fire-and-forget
        if msg_id is None:
            if method == "notifications/initialized":
                self._initialized = True
                logger.info("Client sent initialized notification")
            elif method == "notifications/cancelled":
                logger.info("Client cancelled request %s", params.get("requestId"))
            else:
                logger.debug("Unhandled notification: %s", method)
            return None

        # Requests (have id) — must respond
        try:
            if method == "initialize":
                return self._handle_initialize(msg_id, params)
            elif method == "ping":
                return self._result(msg_id, {})
            elif method == "tools/list":
                return self._handle_tools_list(msg_id)
            elif method == "tools/call":
                return await self._handle_tools_call(msg_id, params)
            else:
                return self._error(msg_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            logger.exception("Error handling %s", method)
            return self._error(msg_id, -32603, str(exc))

    def _handle_initialize(
        self, msg_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to ``initialize`` with server capabilities."""
        logger.info(
            "MCP initialize — client: %s %s",
            params.get("clientInfo", {}).get("name", "unknown"),
            params.get("clientInfo", {}).get("version", ""),
        )
        return self._result(msg_id, {
            "protocolVersion": _MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": _SERVER_NAME,
                "version": _SERVER_VERSION,
            },
        })

    def _handle_tools_list(self, msg_id: Any) -> Dict[str, Any]:
        """Return the list of registered tools."""
        tools_list = []
        for td in self._tools.values():
            tools_list.append({
                "name": td.name,
                "description": td.description,
                "inputSchema": td.input_schema(),
            })
        return self._result(msg_id, {"tools": tools_list})

    async def _handle_tools_call(
        self, msg_id: Any, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Invoke a registered tool handler and return the result."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        td = self._tools.get(tool_name)
        if not td or not td.handler:
            return self._error(msg_id, -32602, f"Unknown tool: {tool_name}")

        try:
            result = await td.handler(arguments, config=self._config)
            return self._result(msg_id, {
                "content": [{"type": "text", "text": self._serialize(result)}],
            })
        except Exception as exc:
            logger.exception("Tool %s failed", tool_name)
            return self._result(msg_id, {
                "content": [{"type": "text", "text": f"Error: {exc}"}],
                "isError": True,
            })

    # -- stdio transport ----------------------------------------------------

    async def run(self, *, input_stream: Any = None, output_stream: Any = None) -> None:
        """Run the MCP server loop, reading from stdin and writing to stdout.

        Parameters
        ----------
        input_stream:
            Override for stdin (useful for testing).
        output_stream:
            Override for stdout (useful for testing).
        """
        reader = input_stream or sys.stdin
        writer = output_stream or sys.stdout

        logger.info("MCP server starting (stdio transport)")

        for line in _read_lines(reader):
            line = line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                error_resp = self._error(None, -32700, f"Parse error: {exc}")
                _write_message(writer, error_resp)
                continue

            # Handle batch requests
            if isinstance(message, list):
                responses = []
                for msg in message:
                    resp = await self.handle_message(msg)
                    if resp is not None:
                        responses.append(resp)
                if responses:
                    _write_message(writer, responses)
            else:
                resp = await self.handle_message(message)
                if resp is not None:
                    _write_message(writer, resp)

    # -- JSON-RPC helpers ---------------------------------------------------

    @staticmethod
    def _result(msg_id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }

    @staticmethod
    def _serialize(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value, indent=2, default=str)


# ===================================================================
# I/O helpers
# ===================================================================

def _read_lines(stream: Any):
    """Yield lines from a stream (works with both sync and file-like objects)."""
    if hasattr(stream, "__iter__"):
        yield from stream
    else:
        while True:
            line = stream.readline()
            if not line:
                break
            yield line


def _write_message(stream: Any, message: Any) -> None:
    """Write a JSON-RPC message as a single newline-terminated line."""
    text = json.dumps(message, separators=(",", ":")) + "\n"
    stream.write(text)
    stream.flush()
