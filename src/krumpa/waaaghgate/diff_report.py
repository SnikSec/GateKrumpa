"""
WaaaghGate — Diff / delta report generator.

Compares two scan results and produces a delta showing new, fixed,
and unchanged findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from krumpa.core import Finding, Severity


class DiffReport:
    """Container for a diff between two scan runs."""

    __slots__ = ("new_findings", "fixed_findings", "unchanged_findings",
                 "baseline_count", "current_count", "timestamp")

    def __init__(
        self,
        new_findings: List[Finding],
        fixed_findings: List[Finding],
        unchanged_findings: List[Finding],
        baseline_count: int,
        current_count: int,
    ) -> None:
        self.new_findings = new_findings
        self.fixed_findings = fixed_findings
        self.unchanged_findings = unchanged_findings
        self.baseline_count = baseline_count
        self.current_count = current_count
        self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def is_improved(self) -> bool:
        return len(self.fixed_findings) > len(self.new_findings)

    @property
    def is_regressed(self) -> bool:
        return len(self.new_findings) > len(self.fixed_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "baseline_count": self.baseline_count,
            "current_count": self.current_count,
            "new": len(self.new_findings),
            "fixed": len(self.fixed_findings),
            "unchanged": len(self.unchanged_findings),
            "new_findings": [_finding_to_dict(f) for f in self.new_findings],
            "fixed_findings": [_finding_to_dict(f) for f in self.fixed_findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class DiffReporter:
    """Compare baseline and current findings to produce a delta."""

    @staticmethod
    def compute_diff(
        baseline: List[Finding],
        current: List[Finding],
    ) -> DiffReport:
        """Compare two lists of findings and return a DiffReport."""
        baseline_keys = {_finding_key(f): f for f in baseline}
        current_keys = {_finding_key(f): f for f in current}

        baseline_set = set(baseline_keys.keys())
        current_set = set(current_keys.keys())

        new_keys = current_set - baseline_set
        fixed_keys = baseline_set - current_set
        unchanged_keys = baseline_set & current_set

        return DiffReport(
            new_findings=[current_keys[k] for k in sorted(new_keys)],
            fixed_findings=[baseline_keys[k] for k in sorted(fixed_keys)],
            unchanged_findings=[baseline_keys[k] for k in sorted(unchanged_keys)],
            baseline_count=len(baseline),
            current_count=len(current),
        )

    @staticmethod
    def format_markdown(report: DiffReport) -> str:
        """Format a DiffReport as a Markdown summary."""
        lines = [
            "# Scan Diff Report",
            "",
            f"**Baseline:** {report.baseline_count} findings",
            f"**Current:** {report.current_count} findings",
            "",
        ]

        if report.is_improved:
            lines.append(f"**Status: IMPROVED** ({len(report.fixed_findings)} fixed, {len(report.new_findings)} new)")
        elif report.is_regressed:
            lines.append(f"**Status: REGRESSED** ({len(report.new_findings)} new, {len(report.fixed_findings)} fixed)")
        else:
            lines.append(f"**Status: UNCHANGED** ({len(report.new_findings)} new, {len(report.fixed_findings)} fixed)")

        lines.append("")

        if report.new_findings:
            lines.append("## New Findings")
            lines.append("")
            for f in report.new_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                cwe = f" (CWE-{f.cwe})" if f.cwe else ""
                lines.append(f"- **[{sev}]** {f.title}{cwe}")
            lines.append("")

        if report.fixed_findings:
            lines.append("## Fixed Findings")
            lines.append("")
            for f in report.fixed_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                cwe = f" (CWE-{f.cwe})" if f.cwe else ""
                lines.append(f"- ~~[{sev}] {f.title}{cwe}~~")
            lines.append("")

        lines.append(f"---\n*Generated: {report.timestamp}*")
        return "\n".join(lines)


def _finding_key(f: Finding) -> str:
    """Generate a dedup key for a finding."""
    target_str = ""
    if f.target:
        target_str = f"{getattr(f.target, 'method', '')}:{getattr(f.target, 'url', '')}"
    return f"{f.title}|{f.cwe or ''}|{target_str}"


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
    result: Dict[str, Any] = {
        "title": f.title,
        "severity": sev,
    }
    if f.cwe:
        result["cwe"] = f.cwe
    if f.target:
        result["target"] = f"{getattr(f.target, 'method', '')} {getattr(f.target, 'url', '')}"
    return result
