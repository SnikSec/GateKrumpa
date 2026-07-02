"""
WaaaghGate — PR/MR annotation generator.

Produces inline review comments for GitHub and GitLab merge/pull requests.
Transforms scan findings into structured annotation objects that can be
posted via the respective platform APIs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.waaaghgate.pr_annotator")


@dataclass
class PrAnnotation:
    """A single inline annotation for a PR/MR."""
    path: str  # relative file path
    line: int  # line number (1-based)
    end_line: Optional[int] = None
    message: str = ""
    severity: str = "warning"  # "error", "warning", "notice"
    title: str = ""
    annotation_level: str = "warning"  # GitHub: "failure", "warning", "notice"


@dataclass
class PrReport:
    """Full PR report with summary and inline annotations."""
    title: str
    summary: str
    conclusion: str  # "success", "failure", "neutral"
    annotations: List[PrAnnotation] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)


_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "failure",
    Severity.HIGH: "failure",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


class PrAnnotator:
    """
    Converts scan findings into PR/MR annotations for GitHub Actions
    and GitLab CI.
    """

    def __init__(
        self,
        *,
        platform: str = "github",
        fail_on: Optional[Severity] = Severity.HIGH,
    ) -> None:
        self._platform = platform.lower()
        self._fail_on = fail_on

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        findings: List[Finding],
        *,
        file_mapping: Optional[Dict[str, str]] = None,
    ) -> PrReport:
        """
        Generate a PR report from scan findings.

        *file_mapping* maps endpoint URLs to file paths (for spec-driven
        scanners that know which spec file defines each endpoint).
        """
        annotations = self._build_annotations(findings, file_mapping or {})
        stats = self._build_stats(findings)

        should_fail = any(
            self._severity_fails(f.severity)
            for f in findings
        )

        conclusion = "failure" if should_fail else "success"
        if not findings:
            conclusion = "success"

        summary_parts = [
            f"**GateKrumpa Security Scan**: {len(findings)} finding(s)",
            "",
        ]
        for sev_name, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            summary_parts.append(f"- {sev_name}: {count}")

        if should_fail:
            summary_parts.append("")
            summary_parts.append(
                f"**Gate: FAILED** — findings at or above "
                f"{self._fail_on.value if self._fail_on else 'N/A'} severity."
            )

        return PrReport(
            title="GateKrumpa Security Scan",
            summary="\n".join(summary_parts),
            conclusion=conclusion,
            annotations=annotations,
            stats=stats,
        )

    def to_github_annotations(
        self, report: PrReport,
    ) -> List[Dict[str, Any]]:
        """
        Convert report to GitHub Check Run annotation format.

        See: https://docs.github.com/en/rest/checks/runs
        """
        results: List[Dict[str, Any]] = []
        for ann in report.annotations:
            entry: Dict[str, Any] = {
                "path": ann.path,
                "start_line": ann.line,
                "end_line": ann.end_line or ann.line,
                "annotation_level": ann.annotation_level,
                "message": ann.message,
                "title": ann.title,
            }
            results.append(entry)
        return results

    def to_gitlab_notes(
        self, report: PrReport,
    ) -> List[Dict[str, Any]]:
        """
        Convert report to GitLab MR discussion note format.

        See: https://docs.gitlab.com/ee/api/discussions.html
        """
        results: List[Dict[str, Any]] = []
        for ann in report.annotations:
            note: Dict[str, Any] = {
                "body": f"### {ann.title}\n\n{ann.message}",
                "position": {
                    "position_type": "text",
                    "new_path": ann.path,
                    "new_line": ann.line,
                },
            }
            results.append(note)
        return results

    def to_sarif(
        self,
        findings: List[Finding],
        *,
        file_mapping: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Convert findings to SARIF 2.1.0 format for GitHub Code Scanning.
        """
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        rule_ids: Dict[str, int] = {}

        for finding in findings:
            rule_id = f"GK-{finding.cwe or 0}"
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description[:512]},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity),
                    },
                })

            file_path = (file_mapping or {}).get(
                finding.target.url if finding.target else "",
                "unknown",
            )

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": 1},
                    },
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
                        "rules": rules,
                    },
                },
                "results": results,
            }],
        }

    def format_summary_comment(
        self, report: PrReport,
    ) -> str:
        """
        Generate a markdown summary comment for the PR.
        """
        lines = [
            "## 🔒 GateKrumpa Security Scan",
            "",
            f"**Result: {'❌ FAILED' if report.conclusion == 'failure' else '✅ PASSED'}**",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = report.stats.get(sev_name, 0)
            if count > 0:
                lines.append(f"| {sev_name} | {count} |")

        total = sum(report.stats.values())
        lines.append(f"| **Total** | **{total}** |")
        lines.append("")

        if report.annotations:
            lines.append(f"<details><summary>📋 {len(report.annotations)} inline annotations</summary>")
            lines.append("")
            for ann in report.annotations[:25]:  # cap at 25
                lines.append(f"- **{ann.title}** ({ann.path}:{ann.line})")
            if len(report.annotations) > 25:
                lines.append(f"- ... and {len(report.annotations) - 25} more")
            lines.append("")
            lines.append("</details>")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_annotations(
        self,
        findings: List[Finding],
        file_mapping: Dict[str, str],
    ) -> List[PrAnnotation]:
        annotations: List[PrAnnotation] = []

        for finding in findings:
            url = finding.target.url if finding.target else ""
            path = file_mapping.get(url, "openapi.yaml")

            level = _SEVERITY_TO_LEVEL.get(finding.severity, "warning")

            msg_parts = [finding.description]
            if finding.evidence:
                msg_parts.append(f"\nEvidence: {finding.evidence[:200]}")
            if finding.remediation:
                msg_parts.append(f"\nRemediation: {finding.remediation[:200]}")

            annotations.append(PrAnnotation(
                path=path,
                line=1,
                message="\n".join(msg_parts),
                severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                title=finding.title,
                annotation_level=level,
            ))

        return annotations

    @staticmethod
    def _build_stats(findings: List[Finding]) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        for f in findings:
            key = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            stats[key] = stats.get(key, 0) + 1
        return stats

    def _severity_fails(self, severity: Severity) -> bool:
        if self._fail_on is None:
            return False
        sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        try:
            return sev_order.index(severity) >= sev_order.index(self._fail_on)
        except ValueError:
            return False

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")
