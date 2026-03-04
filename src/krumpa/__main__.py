"""
GateKrumpa CLI — ``python -m krumpa`` entry-point.

Usage:
    gatekrumpa scan   --target URL [--modules m1,m2] [--config FILE] [--spec URL]
    gatekrumpa modules list
    gatekrumpa modules info MODULE
    gatekrumpa report  --input FILE --format FORMAT
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from krumpa.core import ScanContext, Target
from krumpa.core.auth import AuthProvider
from krumpa.core.credentials import build_provider, resolve_config as _resolve_creds
from krumpa.core.engine import ScanEngine
from krumpa.core.reporting import to_json, to_sarif, to_markdown, to_html, to_junit


# ------------------------------------------------------------------
# Module registry — canonical name → (import path, class)
# ------------------------------------------------------------------

_MODULE_REGISTRY: dict[str, tuple[str, str]] = {
    "sneakygits":  ("krumpa.sneakygits.module",  "SneakyGitsModule"),
    "bosskey":     ("krumpa.bosskey.module",      "BossKeyModule"),
    "waaaghlogic": ("krumpa.waaaghlogic.module",  "WaaaghLogicModule"),
    "grotassault": ("krumpa.grotassault.module",   "GrotAssaultModule"),
    "redteef":     ("krumpa.redteef.module",       "RedTeefModule"),
    "waaaghgate":  ("krumpa.waaaghgate.module",    "WaaaghGateModule"),
    "openkrump":   ("krumpa.openkrump.module",     "OpenKrumpModule"),
}

# Default pipeline order
_DEFAULT_ORDER = [
    "sneakygits", "openkrump", "bosskey",
    "waaaghlogic", "grotassault", "redteef", "waaaghgate",
]


def _load_module_class(name: str):
    """Lazily import and return a module class by its short name."""
    import importlib
    if name not in _MODULE_REGISTRY:
        raise click.BadParameter(
            f"Unknown module {name!r}. "
            f"Available: {', '.join(sorted(_MODULE_REGISTRY))}"
        )
    mod_path, cls_name = _MODULE_REGISTRY[name]
    py_mod = importlib.import_module(mod_path)
    return getattr(py_mod, cls_name)


def _load_config(path: Optional[str]) -> dict:
    """Load a YAML or JSON config file. Returns empty dict if no path given."""
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise click.BadParameter(f"Config file not found: {path}")

    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise click.UsageError(
                "PyYAML is required for YAML config files.  "
                "Install with: pip install pyyaml"
            )
        return yaml.safe_load(text) or {}
    else:
        return json.loads(text)


def _setup_logging(verbose: int) -> None:
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _collect_targets(
    cli_targets: tuple[str, ...],
    targets_file: Optional[str],
    config: dict,
) -> list[Target]:
    """Merge targets from CLI flags, a file, and the config YAML.

    Sources (in priority order — all are merged, no override):
      1. ``--target`` CLI flags (repeatable)
      2. ``--targets-file`` (one URL per line)
      3. ``campaign.targets`` list in the config file (each entry is
         either a URL string or a dict with ``url``, ``method``, etc.)

    Returns a deduplicated list of :class:`Target` objects.
    """
    seen: set[str] = set()
    result: list[Target] = []

    def _add(t: Target) -> None:
        key = f"{t.method}:{t.url}"
        if key not in seen:
            seen.add(key)
            result.append(t)

    # 1. CLI --target flags
    for url in cli_targets:
        _add(Target(url=url.strip()))

    # 2. Targets file
    if targets_file:
        p = Path(targets_file)
        if not p.exists():
            raise click.BadParameter(f"Targets file not found: {targets_file}")
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                _add(Target(url=line))

    # 3. Config campaign.targets
    campaign_targets = config.get("campaign", {}).get("targets", [])
    for entry in campaign_targets:
        if isinstance(entry, str):
            _add(Target(url=entry))
        elif isinstance(entry, dict) and "url" in entry:
            _add(Target(
                url=entry["url"],
                method=entry.get("method", "GET"),
                headers=entry.get("headers", {}),
                body=entry.get("body"),
                metadata=entry.get("metadata", {}),
            ))

    return result


# ------------------------------------------------------------------
# CLI group
# ------------------------------------------------------------------

@click.group()
@click.version_option("0.1.0", prog_name="gatekrumpa")
@click.option("-v", "--verbose", count=True, help="Increase verbosity (-v info, -vv debug).")
def cli(verbose: int) -> None:
    """GateKrumpa — modular API security testing platform."""
    _setup_logging(verbose)


# ------------------------------------------------------------------
# scan command
# ------------------------------------------------------------------

@cli.command()
@click.option(
    "--target", "-t", "targets", multiple=True,
    help="Base URL(s) to scan (repeatable: -t URL1 -t URL2).",
)
@click.option(
    "--targets-file", "targets_file", default=None,
    help="Path to a file with one target URL per line.",
)
@click.option(
    "--modules", "-m", default=None,
    help="Comma-separated module names (default: all in pipeline order).",
)
@click.option("--config", "-c", "config_path", default=None, help="Path to YAML/JSON config file.")
@click.option("--spec", default=None, help="OpenAPI spec URL (passed to openkrump).")
@click.option(
    "--format", "-f", "formats", default="json",
    help="Comma-separated output formats: json, sarif, markdown, html, junit (default: json).",
)
@click.option("--output", "-o", default=None, help="Output directory for reports (default: stdout).")
def scan(
    targets: tuple[str, ...],
    targets_file: Optional[str],
    modules: Optional[str],
    config_path: Optional[str],
    spec: Optional[str],
    formats: str,
    output: Optional[str],
) -> None:
    """Run a security scan against one or more target URLs."""
    config = _load_config(config_path)

    # ── Credential resolution ──────────────────────────────────────
    # Build provider chain (env vars + optional vault) and resolve all
    # ${VAR} / vault:// references in the config before anything reads it.
    cred_provider = build_provider(config)
    config = _resolve_creds(config, cred_provider)

    # Collect all targets: CLI flags + file + config
    all_targets = _collect_targets(targets, targets_file, config)
    if not all_targets:
        raise click.UsageError(
            "No targets specified. Use --target, --targets-file, "
            "or add campaign.targets in the config file."
        )

    # Determine modules
    if modules:
        module_names = [m.strip().lower() for m in modules.split(",")]
    elif "modules" in config.get("scan", {}):
        module_names = config["scan"]["modules"]
    else:
        module_names = list(_DEFAULT_ORDER)

    # Determine formats
    format_list = [f.strip().lower() for f in formats.split(",")]

    # ── HTTP / Auth wiring ─────────────────────────────────────────
    http_section: dict = dict(config.get("http", {}))
    auth_section: dict = http_section.pop("auth", {})

    auth_provider: Optional[AuthProvider] = None
    if auth_section:
        auth_provider = AuthProvider(**auth_section)
        http_section["auth"] = auth_provider

    # Build context
    ctx = ScanContext(config=config)
    for t in all_targets:
        ctx.add_target(t)

    # Populate auth_tokens so modules like BossKey have access
    if auth_provider and auth_provider.auth_type != "none":
        ctx.auth_tokens["_provider_type"] = auth_provider.auth_type

    # Build engine (pass resolved HTTP config including auth)
    engine = ScanEngine(ctx=ctx, http_config=http_section)
    for name in module_names:
        cls = _load_module_class(name)
        kwargs = _module_kwargs(name, config, spec=spec)
        engine.register(cls(**kwargs))

    target_summary = ", ".join(t.url for t in all_targets[:5])
    if len(all_targets) > 5:
        target_summary += f" (+{len(all_targets) - 5} more)"
    click.echo(f"Starting scan against {target_summary}")
    click.echo(f"Targets: {len(all_targets)}")
    click.echo(f"Modules: {', '.join(module_names)}")
    click.echo(f"Formats: {', '.join(format_list)}")
    click.echo("---")

    # Run
    result_ctx = asyncio.run(engine.run_all())

    # Summary
    summary = result_ctx.summary()
    click.echo(f"\nScan complete — {summary['total_findings']} finding(s)")
    for sev, count in sorted(summary["findings_by_severity"].items()):
        click.echo(f"  {sev.upper()}: {count}")

    # Generate reports
    _write_reports(result_ctx, format_list, output)

    # Exit code: 1 if any HIGH or CRITICAL
    has_critical = summary["findings_by_severity"].get("critical", 0) > 0
    has_high = summary["findings_by_severity"].get("high", 0) > 0
    if has_critical or has_high:
        sys.exit(1)


def _module_kwargs(name: str, config: dict, *, spec: Optional[str] = None) -> dict:
    """Extract constructor kwargs for a module from the config dict.

    Reads ``config[name]`` (the per-module YAML section) and forwards
    every key whose name matches a constructor parameter of the target
    module class.  Keys that don't correspond to a constructor param
    are silently ignored so the config file is forward-compatible.

    Known key aliases (YAML name → constructor param) are handled
    automatically, e.g. ``strict_mode`` → ``strict``.
    """
    # Keys that should never be forwarded — they are injected at runtime
    _RUNTIME_ONLY = frozenset({"http_client", "reporter"})

    # YAML key → constructor param name (for config/code name mismatches)
    _KEY_ALIASES: dict[str, dict[str, str]] = {
        "openkrump": {"strict_mode": "strict"},
    }

    mod_config: dict = dict(config.get(name, {}))
    kwargs: dict = {}

    # CLI-level overrides
    if name == "openkrump" and spec:
        kwargs["spec_url"] = spec

    if not mod_config:
        return kwargs

    # Discover which params the module constructor actually accepts
    cls = _load_module_class(name)
    sig = inspect.signature(cls.__init__)
    valid_params = {
        p.name for p in sig.parameters.values()
        if p.name != "self"
    } - _RUNTIME_ONLY

    # Apply aliases for this module
    aliases = _KEY_ALIASES.get(name, {})
    for yaml_key, param_name in aliases.items():
        if yaml_key in mod_config and param_name not in mod_config:
            mod_config[param_name] = mod_config.pop(yaml_key)

    # Forward matching keys
    for key, value in mod_config.items():
        if key in valid_params and key not in kwargs:
            kwargs[key] = value

    return kwargs


def _write_reports(ctx: ScanContext, formats: list[str], output_dir: Optional[str]) -> None:
    """Generate and write reports in the requested formats."""
    out_path = Path(output_dir) if output_dir else None
    if out_path:
        out_path.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        if fmt == "json":
            content = to_json(ctx)
            ext = "json"
        elif fmt == "sarif":
            content = json.dumps(to_sarif(ctx), indent=2)
            ext = "sarif.json"
        elif fmt == "markdown":
            content = to_markdown(ctx)
            ext = "md"
        elif fmt == "html":
            content = to_html(ctx)
            ext = "html"
        elif fmt == "junit":
            content = to_junit(ctx)
            ext = "junit.xml"
        else:
            click.echo(f"Unknown format: {fmt!r} — skipping", err=True)
            continue

        if out_path:
            dest = out_path / f"gatekrumpa-report.{ext}"
            dest.write_text(content, encoding="utf-8")
            click.echo(f"Report written: {dest}")
        else:
            click.echo(f"\n--- {fmt.upper()} Report ---")
            click.echo(content)


# ------------------------------------------------------------------
# modules command group
# ------------------------------------------------------------------

@cli.group("modules")
def modules_group() -> None:
    """List and inspect available modules."""


@modules_group.command("list")
def modules_list() -> None:
    """List all available modules."""
    click.echo("Available modules:\n")
    for name in _DEFAULT_ORDER:
        cls = _load_module_class(name)
        inst = cls.__new__(cls)
        desc = getattr(inst, "description", "")
        click.echo(f"  {name:<14}  {desc}")


@modules_group.command("info")
@click.argument("module_name")
def modules_info(module_name: str) -> None:
    """Show detailed information about a module."""
    name = module_name.strip().lower()
    cls = _load_module_class(name)
    inst = cls.__new__(cls)
    click.echo(f"Module:      {getattr(inst, 'name', name)}")
    click.echo(f"Class:       {cls.__qualname__}")
    click.echo(f"Description: {getattr(inst, 'description', 'N/A')}")


# ------------------------------------------------------------------
# report command
# ------------------------------------------------------------------

@cli.command()
@click.option("--input", "-i", "input_path", required=True, help="Path to JSON scan results.")
@click.option(
    "--format", "-f", "fmt", required=True,
    type=click.Choice(["json", "sarif", "markdown", "html", "junit"], case_sensitive=False),
    help="Output format.",
)
@click.option("--output", "-o", default=None, help="Output file path (default: stdout).")
def report(input_path: str, fmt: str, output: Optional[str]) -> None:
    """Convert saved scan results to a different format."""
    p = Path(input_path)
    if not p.exists():
        raise click.BadParameter(f"Input file not found: {input_path}")

    data = json.loads(p.read_text(encoding="utf-8"))

    # Reconstruct a minimal ScanContext from the JSON
    ctx = ScanContext(scan_id=data.get("scan_id", "unknown"))
    from krumpa.core import Finding, Severity
    for fd in data.get("findings", []):
        target = None
        if fd.get("target"):
            target = Target(url=fd["target"])
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

    if fmt == "json":
        content = to_json(ctx)
    elif fmt == "sarif":
        content = json.dumps(to_sarif(ctx), indent=2)
    elif fmt == "html":
        content = to_html(ctx)
    elif fmt == "junit":
        content = to_junit(ctx)
    else:
        content = to_markdown(ctx)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Report written: {output}")
    else:
        click.echo(content)


# ------------------------------------------------------------------
# import command
# ------------------------------------------------------------------

@cli.command("import")
@click.option("--input", "-i", "input_path", required=True, help="Path to file to import.")
@click.option(
    "--format", "-f", "fmt", required=True,
    type=click.Choice(["har", "burp", "zap"], case_sensitive=False),
    help="Input format: har (HAR 1.2), burp (Burp XML), zap (ZAP JSON).",
)
@click.option("--output", "-o", default=None, help="Output JSON file for imported targets (default: stdout).")
def import_cmd(input_path: str, fmt: str, output: Optional[str]) -> None:
    """Import targets and traffic from external tools (Burp, ZAP, HAR)."""
    from krumpa.core.exchange import import_har, import_burp_xml, import_zap_json

    p = Path(input_path)
    if not p.exists():
        raise click.BadParameter(f"Input file not found: {input_path}")

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
        raise click.BadParameter(f"Unknown format: {fmt}")

    result = {
        "targets": [{"url": t.url, "method": t.method} for t in targets],
        "records": len(records),
    }

    click.echo(f"Imported {len(targets)} target(s) and {len(records)} request record(s) from {fmt.upper()}")

    content = json.dumps(result, indent=2)
    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Written to: {output}")
    else:
        click.echo(content)


# ------------------------------------------------------------------
# export command
# ------------------------------------------------------------------

@cli.command("export")
@click.option("--input", "-i", "input_path", required=True, help="Path to GateKrumpa JSON scan results.")
@click.option(
    "--format", "-f", "fmt", required=True,
    type=click.Choice(["har"], case_sensitive=False),
    help="Export format (currently: har).",
)
@click.option("--output", "-o", default=None, help="Output file (default: stdout).")
def export_cmd(input_path: str, fmt: str, output: Optional[str]) -> None:
    """Export recorded traffic to external formats (HAR)."""
    from krumpa.core.exchange import export_har
    from krumpa.core.recorder import RequestRecord

    p = Path(input_path)
    if not p.exists():
        raise click.BadParameter(f"Input file not found: {input_path}")

    data = json.loads(p.read_text(encoding="utf-8"))

    # Reconstruct RequestRecords from JSON
    records: list[RequestRecord] = []
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
    content = json.dumps(har, indent=2)

    click.echo(f"Exported {len(records)} record(s) to HAR format")
    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Written to: {output}")
    else:
        click.echo(content)


# ------------------------------------------------------------------
# generate-sdk command
# ------------------------------------------------------------------

@cli.command("generate-sdk")
@click.option("--spec", "-s", "spec_path", required=True, help="Path or URL to OpenAPI/Swagger spec (JSON/YAML).")
@click.option("--output", "-o", default=None, help="Output file (default: stdout).")
@click.option("--class-name", default="ApiClient", help="Name for the generated client class.")
@click.option("--base-url", default=None, help="Override the base URL from the spec.")
def generate_sdk_cmd(
    spec_path: str,
    output: Optional[str],
    class_name: str,
    base_url: Optional[str],
) -> None:
    """Generate a typed Python SDK client from an OpenAPI/Swagger spec."""
    from krumpa.openkrump.parser import SpecParser
    from krumpa.openkrump.sdk_generator import generate_sdk

    # Load spec
    spec_data = _load_spec(spec_path)

    # Parse
    parser = SpecParser(base_url=base_url)
    endpoints = parser.parse(spec_data)

    if not endpoints:
        click.echo("No endpoints found in the spec.", err=True)
        raise SystemExit(1)

    resolved_base = base_url or parser.resolve_url(spec_data, "")
    code = generate_sdk(
        spec_data,
        endpoints,
        resolved_base,
        class_name=class_name,
    )

    click.echo(f"Generated SDK: {class_name} with {len(endpoints)} method(s)")
    if output:
        Path(output).write_text(code, encoding="utf-8")
        click.echo(f"Written to: {output}")
    else:
        click.echo(code)


def _load_spec(spec_path: str) -> dict:
    """Load an OpenAPI spec from a file path or URL."""
    if spec_path.startswith(("http://", "https://")):
        import httpx
        resp = httpx.get(spec_path, follow_redirects=True, timeout=30)
        resp.raise_for_status()
        if spec_path.endswith((".yaml", ".yml")):
            try:
                import yaml  # type: ignore[import-untyped]
                return yaml.safe_load(resp.text)  # type: ignore[no-any-return]
            except ImportError:
                raise click.UsageError("PyYAML is required to parse YAML specs. Install it with: pip install pyyaml")
        return resp.json()  # type: ignore[no-any-return]

    p = Path(spec_path)
    if not p.exists():
        raise click.BadParameter(f"Spec file not found: {spec_path}")

    text = p.read_text(encoding="utf-8")
    if spec_path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore[import-untyped]
            return yaml.safe_load(text)  # type: ignore[no-any-return]
        except ImportError:
            raise click.UsageError("PyYAML is required to parse YAML specs. Install it with: pip install pyyaml")
    return json.loads(text)  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# mcp-serve command
# ------------------------------------------------------------------

@cli.command("mcp-serve")
@click.option("--config", "-c", "config_path", default=None, help="Path to YAML/JSON config file.")
def mcp_serve(config_path: Optional[str]) -> None:
    """Start the GateKrumpa MCP server (stdio transport).

    The server exposes scan, report, import/export, and SDK generation
    tools over the Model Context Protocol so AI agents can invoke them.

    Credential references (``${VAR}``, ``vault://``) in the config are
    resolved before any tool handler runs — agents never see raw secrets.

    Example MCP client config (Claude Desktop, VS Code, etc.)::

        {
          "mcpServers": {
            "gatekrumpa": {
              "command": "gatekrumpa",
              "args": ["mcp-serve", "--config", "configs/default.yaml"]
            }
          }
        }
    """
    from krumpa.mcp.server import McpServer
    from krumpa.mcp.tools import register_default_tools

    config = _load_config(config_path)

    # Resolve credential references
    cred_provider = build_provider(config)
    config = _resolve_creds(config, cred_provider)

    server = McpServer(config=config)
    register_default_tools(server, config)

    click.echo("GateKrumpa MCP server starting (stdio)…", err=True)
    asyncio.run(server.run())


# ------------------------------------------------------------------
# Entry-point
# ------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
