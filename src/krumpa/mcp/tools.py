"""
GateKrumpa MCP tools — bridge between MCP protocol and scan engine.

Each tool is a thin async wrapper that translates MCP ``arguments``
into existing GateKrumpa API calls and returns structured results.

Security: tool handlers receive the **already-resolved** config dict
(credentials interpolated by the provider chain), so raw secrets never
surface in MCP messages.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from krumpa.mcp.server import McpServer, ToolDefinition, ToolParameter

logger = logging.getLogger("krumpa.mcp.tools")


def register_default_tools(server: McpServer, config: Optional[Dict[str, Any]] = None) -> None:
    """Register all built-in GateKrumpa tools on *server*."""
    _config = config or {}
    server.register_tool(_scan_tool(_config))
    server.register_tool(_list_modules_tool())
    server.register_tool(_module_info_tool())
    server.register_tool(_report_tool())
    server.register_tool(_import_tool())
    server.register_tool(_export_tool())
    server.register_tool(_generate_sdk_tool())


# ===================================================================
# Tool: scan
# ===================================================================

def _scan_tool(config: Dict[str, Any]) -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        return await _run_scan(args, config)

    return ToolDefinition(
        name="gatekrumpa_scan",
        description=(
            "Run a GateKrumpa security scan against one or more target URLs. "
            "Returns findings with severity, evidence, and remediation."
        ),
        parameters=[
            ToolParameter(
                name="targets",
                description="List of target URLs to scan.",
                type="array",
                required=True,
            ),
            ToolParameter(
                name="modules",
                description=(
                    "Comma-separated module names to run. Available: "
                    "sneakygits, openkrump, bosskey, waaaghlogic, "
                    "grotassault, redteef, waaaghgate. "
                    "Omit to run all in default pipeline order."
                ),
                type="string",
            ),
            ToolParameter(
                name="spec_url",
                description="OpenAPI spec URL (passed to the openkrump module).",
                type="string",
            ),
        ],
        handler=_handler,
    )


async def _run_scan(args: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a scan and return the summary + findings."""
    from krumpa.core import ScanContext, Target
    from krumpa.core.auth import AuthProvider
    from krumpa.core.engine import ScanEngine

    # Lazy import to avoid pulling in all modules at MCP startup
    from krumpa.__main__ import (
        _DEFAULT_ORDER,  # pyright: ignore[reportPrivateUsage]
        _load_module_class,  # pyright: ignore[reportPrivateUsage]
        _module_kwargs,  # pyright: ignore[reportPrivateUsage]
    )

    targets_raw: Any = args.get("targets", [])
    if isinstance(targets_raw, str):
        targets_raw = [t.strip() for t in targets_raw.split(",") if t.strip()]

    if not targets_raw:
        return {"error": "No targets specified."}

    # Module selection
    modules_str: Optional[str] = args.get("modules")
    if modules_str:
        module_names = [m.strip().lower() for m in modules_str.split(",")]
    else:
        module_names = list(_DEFAULT_ORDER)

    spec: Optional[str] = args.get("spec_url")

    # HTTP / auth from resolved config
    http_section: Dict[str, Any] = dict(config.get("http", {}))
    auth_section: Dict[str, Any] = http_section.pop("auth", {})
    if auth_section:
        http_section["auth"] = AuthProvider(**auth_section)

    ctx = ScanContext(config=config)
    for url in targets_raw:
        ctx.add_target(Target(url=url))

    engine = ScanEngine(ctx=ctx, http_config=http_section)
    for name in module_names:
        cls = _load_module_class(name)
        kwargs = _module_kwargs(name, config, spec=spec)
        engine.register(cls(**kwargs))

    result_ctx = await engine.run_all()
    summary = result_ctx.summary()

    findings = [f.to_dict() for f in result_ctx.findings]

    return {
        "scan_id": summary["scan_id"],
        "total_targets": summary["total_targets"],
        "total_findings": summary["total_findings"],
        "findings_by_severity": summary["findings_by_severity"],
        "findings": findings,
    }


# ===================================================================
# Tool: list_modules
# ===================================================================

def _list_modules_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.__main__ import _DEFAULT_ORDER, _load_module_class  # pyright: ignore[reportPrivateUsage]

        modules = []
        for name in _DEFAULT_ORDER:
            cls = _load_module_class(name)
            inst = cls.__new__(cls)
            modules.append({
                "name": name,
                "class": cls.__qualname__,
                "description": getattr(inst, "description", ""),
            })
        return {"modules": modules}

    return ToolDefinition(
        name="gatekrumpa_list_modules",
        description="List all available GateKrumpa scan modules with descriptions.",
        parameters=[],
        handler=_handler,
    )


# ===================================================================
# Tool: module_info
# ===================================================================

def _module_info_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.__main__ import _load_module_class  # pyright: ignore[reportPrivateUsage]

        name = args.get("module_name", "").strip().lower()
        if not name:
            return {"error": "module_name is required."}

        try:
            cls = _load_module_class(name)
        except Exception as exc:
            return {"error": str(exc)}

        inst = cls.__new__(cls)
        return {
            "name": getattr(inst, "name", name),
            "class": cls.__qualname__,
            "description": getattr(inst, "description", "N/A"),
            "dependencies": getattr(inst, "dependencies", []),
        }

    return ToolDefinition(
        name="gatekrumpa_module_info",
        description="Get detailed information about a specific GateKrumpa module.",
        parameters=[
            ToolParameter(
                name="module_name",
                description="Module name (e.g. sneakygits, bosskey, grotassault).",
                type="string",
                required=True,
            ),
        ],
        handler=_handler,
    )


# ===================================================================
# Tool: report
# ===================================================================

def _report_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.core import Finding, ScanContext, Severity, Target
        from krumpa.core.reporting import (
            to_html,
            to_json,
            to_junit,
            to_markdown,
            to_sarif,
        )

        input_path = args.get("input_path", "")
        fmt = args.get("format", "json").lower()

        if not input_path:
            return {"error": "input_path is required."}

        p = Path(input_path)
        if not p.exists():
            return {"error": f"Input file not found: {input_path}"}

        data = json.loads(p.read_text(encoding="utf-8"))
        ctx = ScanContext(scan_id=data.get("scan_id", "unknown"))

        for fd in data.get("findings", []):
            target = Target(url=fd["target"]) if fd.get("target") else None
            ctx.add_finding(Finding(
                id=fd.get("id", ""),
                title=fd.get("title", ""),
                description=fd.get("description", ""),
                severity=Severity(fd.get("severity", "info")),
                module=fd.get("module", ""),
                target=target,
                evidence=fd.get("evidence", ""),
                remediation=fd.get("remediation", ""),
                cwe=fd.get("cwe"),
                cvss_score=fd.get("cvss_score"),
                tags=fd.get("tags", []),
            ))

        formatters = {
            "json": to_json,
            "sarif": lambda c: json.dumps(to_sarif(c), indent=2),
            "markdown": to_markdown,
            "html": to_html,
            "junit": to_junit,
        }

        fn = formatters.get(fmt)
        if not fn:
            return {"error": f"Unknown format: {fmt}. Use: json, sarif, markdown, html, junit"}

        content = fn(ctx)
        return {"format": fmt, "content": content}

    return ToolDefinition(
        name="gatekrumpa_report",
        description="Convert saved GateKrumpa scan results to a different output format.",
        parameters=[
            ToolParameter(
                name="input_path",
                description="Path to JSON scan results file.",
                type="string",
                required=True,
            ),
            ToolParameter(
                name="format",
                description="Output format.",
                type="string",
                required=True,
                enum=["json", "sarif", "markdown", "html", "junit"],
            ),
        ],
        handler=_handler,
    )


# ===================================================================
# Tool: import
# ===================================================================

def _import_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.core.exchange import import_burp_xml, import_har, import_zap_json

        input_path = args.get("input_path", "")
        fmt = args.get("format", "").lower()

        if not input_path:
            return {"error": "input_path is required."}
        if not fmt:
            return {"error": "format is required (har, burp, zap)."}

        p = Path(input_path)
        if not p.exists():
            return {"error": f"Input file not found: {input_path}"}

        raw = p.read_text(encoding="utf-8")

        if fmt == "har":
            data = json.loads(raw)
            targets, records = import_har(data)
        elif fmt == "burp":
            targets, records = import_burp_xml(raw)
        elif fmt == "zap":
            data = json.loads(raw)
            targets, records = import_zap_json(data)
        else:
            return {"error": f"Unknown format: {fmt}. Use: har, burp, zap"}

        return {
            "imported_targets": len(targets),
            "imported_records": len(records),
            "targets": [{"url": t.url, "method": t.method} for t in targets],
        }

    return ToolDefinition(
        name="gatekrumpa_import",
        description="Import targets and traffic from external tools (Burp Suite, ZAP, HAR).",
        parameters=[
            ToolParameter(
                name="input_path",
                description="Path to the file to import.",
                type="string",
                required=True,
            ),
            ToolParameter(
                name="format",
                description="Input format.",
                type="string",
                required=True,
                enum=["har", "burp", "zap"],
            ),
        ],
        handler=_handler,
    )


# ===================================================================
# Tool: export
# ===================================================================

def _export_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.core.exchange import export_har
        from krumpa.core.recorder import RequestRecord

        input_path = args.get("input_path", "")
        if not input_path:
            return {"error": "input_path is required."}

        p = Path(input_path)
        if not p.exists():
            return {"error": f"Input file not found: {input_path}"}

        data = json.loads(p.read_text(encoding="utf-8"))

        records: List[RequestRecord] = []
        for rd in data.get("records", []):
            records.append(RequestRecord(
                method=rd.get("method", "GET"),
                url=rd.get("url", ""),
                status_code=rd.get("status_code", 0),
                request_headers=rd.get("request_headers", {}),
                response_headers=rd.get("response_headers", {}),
                duration_ms=rd.get("duration_ms", 0),
                request_body=rd.get("request_body"),
                response_body_preview=rd.get("response_body_preview", ""),
            ))

        har = export_har(records)
        return {
            "format": "har",
            "records_exported": len(records),
            "content": json.dumps(har, indent=2),
        }

    return ToolDefinition(
        name="gatekrumpa_export",
        description="Export recorded GateKrumpa traffic to HAR format.",
        parameters=[
            ToolParameter(
                name="input_path",
                description="Path to GateKrumpa JSON scan results.",
                type="string",
                required=True,
            ),
        ],
        handler=_handler,
    )


# ===================================================================
# Tool: generate_sdk
# ===================================================================

def _generate_sdk_tool() -> ToolDefinition:
    async def _handler(args: Dict[str, Any], **_kw: Any) -> Dict[str, Any]:
        from krumpa.openkrump.parser import SpecParser
        from krumpa.openkrump.sdk_generator import generate_sdk

        spec_path = args.get("spec_path", "")
        if not spec_path:
            return {"error": "spec_path is required."}

        class_name = args.get("class_name", "ApiClient")
        base_url = args.get("base_url")

        # Load spec (reuse the CLI helper)
        from krumpa.__main__ import _load_spec  # pyright: ignore[reportPrivateUsage]
        try:
            spec_data = _load_spec(spec_path)
        except Exception as exc:
            return {"error": f"Failed to load spec: {exc}"}

        parser = SpecParser(base_url=base_url)
        endpoints = parser.parse(spec_data)

        if not endpoints:
            return {"error": "No endpoints found in the spec."}

        resolved_base = base_url or parser.resolve_url(spec_data, "")
        code = generate_sdk(
            spec_data,
            endpoints,
            resolved_base,
            class_name=class_name,
        )

        return {
            "class_name": class_name,
            "endpoint_count": len(endpoints),
            "code": code,
        }

    return ToolDefinition(
        name="gatekrumpa_generate_sdk",
        description="Generate a typed Python SDK client from an OpenAPI/Swagger spec.",
        parameters=[
            ToolParameter(
                name="spec_path",
                description="Path or URL to the OpenAPI/Swagger spec (JSON/YAML).",
                type="string",
                required=True,
            ),
            ToolParameter(
                name="class_name",
                description="Name for the generated client class.",
                type="string",
                default="ApiClient",
            ),
            ToolParameter(
                name="base_url",
                description="Override the base URL from the spec.",
                type="string",
            ),
        ],
        handler=_handler,
    )
