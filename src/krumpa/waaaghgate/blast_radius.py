"""
WaaaghGate — Blast radius analyzer and contextual severity override.

Replaces raw CVSS-based severity with a risk-adjusted severity that accounts
for:
  - Downstream impact: does this finding participate in an attack chain?
  - Network isolation: is the target isolated or reachable from the internet?
  - Asset criticality: is the target scored as high-value by HVTScorer?
  - Lateral movement potential: does the chain end in credential theft or
    privilege escalation?

Also generates Sankey diagram data for the HTML report showing the
finding → attack chain → impact flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

from krumpa.core import Finding, ScanContext, Severity
from krumpa.core.attack_chain import AttackChain

logger = logging.getLogger("krumpa.waaaghgate.blast_radius")

_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


@dataclass
class BlastRadiusResult:
    """Adjusted severity and impact analysis for a single finding.

    Attributes
    ----------
    finding:
        The original :class:`Finding`.
    original_severity:
        The severity reported by the scanning module.
    adjusted_severity:
        Severity after blast-radius analysis (may be higher or lower).
    adjustment_reason:
        Human-readable explanation of why the severity was adjusted.
    chain_ids:
        IDs of :class:`AttackChain` objects this finding participates in.
    downstream_impact:
        Plain-text summary of the impact if exploited.
    """
    finding: Finding
    original_severity: Severity
    adjusted_severity: Severity
    adjustment_reason: str = ""
    chain_ids: List[str] = field(default_factory=list)
    downstream_impact: str = ""

    @property
    def was_escalated(self) -> bool:
        return _SEVERITY_RANK[self.adjusted_severity] > _SEVERITY_RANK[self.original_severity]

    @property
    def was_deprioritised(self) -> bool:
        return _SEVERITY_RANK[self.adjusted_severity] < _SEVERITY_RANK[self.original_severity]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding.id,
            "finding_title": self.finding.title,
            "original_severity": self.original_severity.value,
            "adjusted_severity": self.adjusted_severity.value,
            "adjustment_reason": self.adjustment_reason,
            "chain_ids": self.chain_ids,
            "downstream_impact": self.downstream_impact,
        }


class BlastRadiusAnalyzer:
    """Compute contextual severity adjustments for all active findings.

    Usage::

        analyzer = BlastRadiusAnalyzer()
        results = analyzer.analyze(ctx)
        ctx.metadata["blast_radius"] = [r.to_dict() for r in results]
    """

    def analyze(self, ctx: ScanContext) -> List[BlastRadiusResult]:
        """Return blast-radius results for all findings in *ctx*."""
        chains: List[AttackChain] = ctx.metadata.get("attack_chains", [])
        hvt_scores: list = ctx.metadata.get("hvt_scores", [])

        # Build lookup: finding_id → list of chains it appears in
        finding_to_chains: Dict[str, List[AttackChain]] = {}
        for chain in chains:
            for step in chain.steps:
                finding_to_chains.setdefault(step.id, []).append(chain)

        # Build lookup: target_url → HVT priority
        url_to_priority: Dict[str, str] = {}
        for score in hvt_scores:
            url_to_priority[score.target.url] = score.priority

        results: List[BlastRadiusResult] = []
        for finding in ctx.findings:
            result = self._analyze_finding(
                finding,
                finding_to_chains.get(finding.id, []),
                url_to_priority,
            )
            results.append(result)

        # Store summary in context
        ctx.metadata["blast_radius"] = [r.to_dict() for r in results]
        return results

    # ------------------------------------------------------------------

    def _analyze_finding(
        self,
        finding: Finding,
        chains: List[AttackChain],
        url_to_priority: Dict[str, str],
    ) -> BlastRadiusResult:
        original = finding.severity
        adjusted = original
        reason = "No adjustment."
        downstream = ""
        chain_ids = [c.chain_id for c in chains]

        target_url = finding.target.url if finding.target else ""
        hvt_priority = url_to_priority.get(target_url, "low")

        if chains:
            # Finding is part of one or more attack chains
            max_blast = max(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(c.blast_radius, 2)
                for c in chains
            )
            chain_titles = "; ".join(c.title for c in chains[:2])
            downstream = f"Part of attack chain(s): {chain_titles}"

            if max_blast == 4:  # critical blast radius
                new_rank = max(_SEVERITY_RANK[original], 4)  # escalate to at least CRITICAL
                if new_rank > _SEVERITY_RANK[original]:
                    adjusted = _RANK_TO_SEVERITY[new_rank]
                    reason = (
                        f"Escalated: finding participates in a CRITICAL blast-radius attack chain "
                        f"({chain_titles})."
                    )
            elif max_blast == 3:  # high blast radius
                new_rank = max(_SEVERITY_RANK[original], 3)
                if new_rank > _SEVERITY_RANK[original]:
                    adjusted = _RANK_TO_SEVERITY[new_rank]
                    reason = f"Escalated: finding participates in a HIGH blast-radius chain ({chain_titles})."

        elif original == Severity.CRITICAL and hvt_priority == "low":
            # High CVSS but isolated target — deprioritise
            adjusted = Severity.HIGH
            reason = (
                "Deprioritised: CRITICAL severity but target is low-priority (isolated "
                "or no attack chain connecting it to high-value assets)."
            )

        elif original == Severity.MEDIUM and hvt_priority == "critical":
            # Low CVSS but on critical asset — escalate
            adjusted = Severity.HIGH
            reason = (
                "Escalated: MEDIUM severity finding on a CRITICAL-priority target "
                "(high-value asset — payment, auth, or AI infrastructure)."
            )

        if adjusted == original:
            reason = "Severity unchanged — no chain escalation or HVT adjustment applies."

        return BlastRadiusResult(
            finding=finding,
            original_severity=original,
            adjusted_severity=adjusted,
            adjustment_reason=reason,
            chain_ids=chain_ids,
            downstream_impact=downstream,
        )

    def generate_sankey_data(self, ctx: ScanContext) -> Dict[str, Any]:
        """Return Sankey diagram data for the HTML report.

        Structure::

            {
              "nodes": [{"id": "...", "label": "...", "type": "finding|chain|impact"}],
              "links": [{"source": "...", "target": "...", "value": 1}]
            }
        """
        chains: List[AttackChain] = ctx.metadata.get("attack_chains", [])
        nodes: List[Dict[str, str]] = []
        links: List[Dict[str, Any]] = []
        seen_nodes: set = set()

        def add_node(nid: str, label: str, ntype: str) -> None:
            if nid not in seen_nodes:
                nodes.append({"id": nid, "label": label[:40], "type": ntype})
                seen_nodes.add(nid)

        for chain in chains:
            chain_id = f"chain_{chain.chain_id}"
            add_node(chain_id, chain.title, "chain")

            for step in chain.steps:
                step_id = f"finding_{step.id}"
                add_node(step_id, step.title[:40], "finding")
                links.append({"source": step_id, "target": chain_id, "value": 1})

            # Chain → impact node
            impact_id = f"impact_{chain.blast_radius}"
            add_node(impact_id, f"{chain.blast_radius.upper()} impact", "impact")
            links.append({"source": chain_id, "target": impact_id, "value": 1})

        return {"nodes": nodes, "links": links}
