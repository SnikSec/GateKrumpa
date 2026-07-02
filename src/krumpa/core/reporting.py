"""
GateKrumpa core — reporting helpers.

Formats scan results into JSON, SARIF, Markdown, HTML, and JUnit XML.
"""

from __future__ import annotations

import html as _html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List

from krumpa.core import Finding, ScanContext, Severity

# Severity precedence used for sorting findings in every format
_SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#fd7e14",
    Severity.MEDIUM: "#ffc107",
    Severity.LOW: "#17a2b8",
    Severity.INFO: "#6c757d",
}


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    """Return findings sorted by severity (critical first)."""
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

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
    """Serialise the full scan context to JSON (findings sorted by severity)."""
    payload = ctx.summary()
    payload["findings"] = [f.to_dict() for f in _sorted_findings(ctx.findings)]
    return json.dumps(payload, indent=indent, default=str)


def to_sarif(ctx: ScanContext) -> Dict[str, Any]:
    """
    Return a SARIF v2.1.0 object for CI/CD ingestion.

    Enhancements over the baseline:
    - ``relatedLocations`` populated from ``ctx.metadata["attack_chains"]``
      so each chain step appears as a related location on the entry-point finding.
    - ``level`` uses blast-radius adjusted severity when available
      (from ``ctx.metadata["blast_radius"]``).
    - ``artifacts`` includes Sankey diagram data from
      ``ctx.metadata["sankey_data"]`` when present.
    """
    # Build blast-radius lookup: finding_id → adjusted_severity
    blast_map: Dict[str, str] = {}
    for br in ctx.metadata.get("blast_radius", []):
        fid = br.get("finding_id", "")
        adj = br.get("adjusted_severity", "")
        if fid and adj:
            blast_map[fid] = adj

    # Build chain step lookup: finding_id → list of other step URLs in chain
    chain_related: Dict[str, List[Dict]] = {}
    for chain in ctx.metadata.get("attack_chains", []):
        for step in chain.steps:
            others = [
                {
                    "message": {"text": f"Attack chain step: {other.title}"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": other.target.url if other.target else "unknown"}
                    },
                }
                for other in chain.steps
                if other.id != step.id
            ]
            if others:
                chain_related.setdefault(step.id, []).extend(others)

    results: List[Dict[str, Any]] = []
    for f in _sorted_findings(ctx.findings):
        # Use blast-radius adjusted severity if available
        effective_severity = blast_map.get(f.id, f.severity.value)
        result: Dict[str, Any] = {
            "ruleId": f.id,
            "level": _sarif_level(effective_severity),
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target.url if f.target else "unknown"}
                }
            }],
        }
        # Attach attack chain related locations
        related = chain_related.get(f.id)
        if related:
            result["relatedLocations"] = related
        results.append(result)

    artifacts: List[Dict[str, Any]] = []
    sankey = ctx.metadata.get("sankey_data")
    if sankey:
        import json as _json
        artifacts.append({
            "location": {"uri": "gatekrumpa-attack-chains-sankey.json"},
            "mimeType": "application/json",
            "contents": {"text": _json.dumps(sankey)},
        })

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "GateKrumpa",
                "version": "0.2.0",
                "informationUri": "https://github.com/GateKrumpa/GateKrumpa",
            }
        },
        "results": results,
    }
    if artifacts:
        run["artifacts"] = artifacts

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
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

    for f in _sorted_findings(ctx.findings):
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


def to_html(ctx: ScanContext) -> str:
    """Self-contained HTML report with severity-sorted findings."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    findings = _sorted_findings(ctx.findings)
    duration_str = ""
    if ctx.started_at and ctx.finished_at:
        dur = (ctx.finished_at - ctx.started_at).total_seconds()
        duration_str = f'<p><strong>Duration:</strong> {dur:.1f}s</p>'

    # Summary cards
    cards_html = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = sum(1 for f in findings if f.severity == sev)
        color = _SEVERITY_COLORS[sev]
        cards_html.append(
            f'<div class="summary-card">'
            f'<div class="count" style="color:{color}">{count}</div>'
            f'<div class="label">{_esc(sev.value)}</div></div>'
        )

    # Finding rows
    rows_html = []
    for i, f in enumerate(findings, 1):
        color = _SEVERITY_COLORS.get(f.severity, "#6c757d")
        target_str = f"{f.target.method} {f.target.url}" if f.target else ""
        cwe_str = f"CWE-{f.cwe}" if f.cwe else ""
        rows_html.append(
            f"<tr>"
            f"<td>{i}</td>"
            f'<td><span class="badge" style="background:{color}">{_esc(f.severity.value)}</span></td>'
            f"<td><strong>{_esc(f.title)}</strong><br><small>{_esc(f.module)}</small></td>"
            f"<td>{_esc(cwe_str)}</td>"
            f"<td><code>{_esc(target_str)}</code></td>"
            f'<td class="evidence">{_esc(f.evidence or "")}</td>'
            f"<td>{_esc(f.remediation or '')}</td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GateKrumpa Scan Report — {_esc(ctx.scan_id)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         line-height: 1.6; color: #212529; background: #f8f9fa; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ margin-bottom: 0.5rem; }}
  .meta {{ color: #6c757d; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .summary-card {{ background: white; border-radius: 8px; padding: 1rem 1.5rem;
                   box-shadow: 0 1px 3px rgba(0,0,0,0.12); min-width: 120px; text-align: center; }}
  .summary-card .count {{ font-size: 2rem; font-weight: bold; }}
  .summary-card .label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
  th {{ background: #343a40; color: white; text-align: left; padding: 0.75rem 1rem; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #dee2e6; vertical-align: top; }}
  tr:hover {{ background: #f1f3f5; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
            color: white; font-size: 0.8rem; font-weight: 600; }}
  .evidence {{ font-family: monospace; font-size: 0.85rem; color: #495057;
               max-width: 400px; word-break: break-all; }}
  code {{ background: #e9ecef; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
  .footer {{ margin-top: 2rem; text-align: center; color: #adb5bd; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>GateKrumpa Scan Report</h1>
  <div class="meta">
    <p><strong>Scan ID:</strong> {_esc(ctx.scan_id)}</p>
    <p><strong>Generated:</strong> {now}</p>
    <p><strong>Targets:</strong> {len(ctx.targets)}</p>
    {duration_str}
    <p><strong>Total findings:</strong> {len(findings)}</p>
  </div>
  <div class="summary">
    {chr(10).join(cards_html)}
  </div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Title / Module</th><th>CWE</th>
        <th>Target</th><th>Evidence</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {chr(10).join(rows_html)}
    </tbody>
  </table>
  <div class="footer">Generated by GateKrumpa &mdash; {now}</div>
</div>
</body>
</html>"""


def to_junit(ctx: ScanContext) -> str:
    """JUnit XML output for CI/CD test-result ingestion.

    Each finding becomes a ``<testcase>`` with a ``<failure>`` element.
    Findings are grouped by module as ``<testsuite>``s.
    """
    suites_el = ET.Element("testsuites")
    suites_el.set("name", "GateKrumpa")
    suites_el.set("tests", str(len(ctx.findings)))

    # Group findings by module
    by_module: Dict[str, List[Finding]] = {}
    for f in _sorted_findings(ctx.findings):
        by_module.setdefault(f.module, []).append(f)

    for module_name, module_findings in by_module.items():
        suite = ET.SubElement(suites_el, "testsuite")
        suite.set("name", module_name)
        suite.set("tests", str(len(module_findings)))
        failures = sum(1 for f in module_findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
        suite.set("failures", str(failures))

        for f in module_findings:
            tc = ET.SubElement(suite, "testcase")
            tc.set("name", f.title)
            tc.set("classname", f"GateKrumpa.{module_name}")
            if f.severity in (Severity.HIGH, Severity.CRITICAL):
                fail_el = ET.SubElement(tc, "failure")
                fail_el.set("message", f.title)
                fail_el.set("type", f.severity.value)
                fail_el.text = f"{f.description}\n\nEvidence: {f.evidence}" if f.evidence else f.description
            elif f.severity == Severity.MEDIUM:
                # medium → system-err (visible but not a failure)
                err = ET.SubElement(tc, "system-err")
                err.text = f"{f.title}: {f.description}"

    return ET.tostring(suites_el, encoding="unicode", xml_declaration=True)


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "none")


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return _html.escape(str(text))
