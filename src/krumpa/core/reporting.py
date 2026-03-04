"""
GateKrumpa core — reporting helpers.

Formats scan results into JSON, SARIF, and human-readable Markdown.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from krumpa.core import ScanContext

# Patterns that should be redacted from evidence / description in reports
_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|token|api_key|bearer|authorization)"
    r"\s*[=:]\s*\S+",
    re.IGNORECASE,
)


def _redact(text: str) -> str:
    """Replace sensitive key=value pairs with redacted placeholders."""
    return _SENSITIVE_RE.sub(
        lambda m: m.group(0).split("=", 1)[0] + "=***REDACTED***"
        if "=" in m.group(0)
        else m.group(0).split(":", 1)[0] + ": ***REDACTED***",
        text,
    )


def to_json(ctx: ScanContext, *, indent: int = 2) -> str:
    """Serialise the full scan context to JSON."""
    payload = ctx.summary()
    payload["findings"] = [f.to_dict() for f in ctx.findings]
    return json.dumps(payload, indent=indent, default=str)


def to_sarif(ctx: ScanContext) -> Dict[str, Any]:
    """
    Return a minimal SARIF v2.1.0 object for CI/CD ingestion.
    """
    results: List[Dict[str, Any]] = []
    for f in ctx.findings:
        results.append({
            "ruleId": f.id,
            "level": _sarif_level(f.severity.value),
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target.url if f.target else "unknown"}
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GateKrumpa",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/GateKrumpa/GateKrumpa",
                }
            },
            "results": results,
        }],
    }


def to_markdown(ctx: ScanContext) -> str:
    """Human-readable Markdown summary."""
    lines = [
        f"# GateKrumpa Scan Report — `{ctx.scan_id}`\n",
        f"**Targets scanned:** {len(ctx.targets)}  ",
        f"**Total findings:** {len(ctx.findings)}\n",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sum(1 for f in ctx.findings if f.severity.value == sev)
        if count:
            lines.append(f"- **{sev.upper()}**: {count}")
    lines.append("\n---\n")

    for f in ctx.findings:
        lines.append(f"## [{f.severity.value.upper()}] {f.title}")
        lines.append(f"**Module:** {f.module}  ")
        if f.target:
            lines.append(f"**Target:** `{f.target.url}`  ")
        lines.append(f"\n{f.description}\n")
        if f.evidence:
            lines.append(f"**Evidence:**\n```\n{_redact(f.evidence)}\n```\n")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}\n")
        lines.append("---\n")

    return "\n".join(lines)


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "none")
