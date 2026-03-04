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
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from krumpa.core import ScanContext, Target
from krumpa.core.engine import ScanEngine
from krumpa.core.reporting import to_json, to_sarif, to_markdown


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
@click.option("--target", "-t", required=True, help="Base URL to scan.")
@click.option(
    "--modules", "-m", default=None,
    help="Comma-separated module names (default: all in pipeline order).",
)
@click.option("--config", "-c", "config_path", default=None, help="Path to YAML/JSON config file.")
@click.option("--spec", default=None, help="OpenAPI spec URL (passed to openkrump).")
@click.option(
    "--format", "-f", "formats", default="json",
    help="Comma-separated output formats: json, sarif, markdown (default: json).",
)
@click.option("--output", "-o", default=None, help="Output directory for reports (default: stdout).")
def scan(
    target: str,
    modules: Optional[str],
    config_path: Optional[str],
    spec: Optional[str],
    formats: str,
    output: Optional[str],
) -> None:
    """Run a security scan against a target URL."""
    config = _load_config(config_path)

    # Determine modules
    if modules:
        module_names = [m.strip().lower() for m in modules.split(",")]
    elif "modules" in config.get("scan", {}):
        module_names = config["scan"]["modules"]
    else:
        module_names = list(_DEFAULT_ORDER)

    # Determine formats
    format_list = [f.strip().lower() for f in formats.split(",")]

    # Build context
    ctx = ScanContext(config=config)
    ctx.add_target(Target(url=target))

    # Build engine
    engine = ScanEngine(ctx=ctx)
    for name in module_names:
        cls = _load_module_class(name)
        kwargs = _module_kwargs(name, config, spec=spec)
        engine.register(cls(**kwargs))

    click.echo(f"Starting scan against {target}")
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
    """Extract constructor kwargs for a module from the config dict."""
    # Module-specific config lives under config[module_name]
    _mod_config = config.get(name, {})
    kwargs: dict = {}

    if name == "openkrump" and spec:
        kwargs["spec_url"] = spec

    # Pass through recognized keys from config
    # (Modules ignore unknown kwargs via **kwargs or specific params)
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
    type=click.Choice(["json", "sarif", "markdown"], case_sensitive=False),
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
    else:
        content = to_markdown(ctx)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Report written: {output}")
    else:
        click.echo(content)


# ------------------------------------------------------------------
# Entry-point
# ------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
