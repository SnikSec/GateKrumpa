"""
RedTeef — Evidence quality scoring.

Score and rank confirmation evidence by quality:
exact match > regex canary > timing anomaly > behavioral anomaly.

Used to prioritize findings and reduce false positive reporting.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.redteef.evidence_scoring")


class EvidenceType(IntEnum):
    """Evidence types ordered by quality (higher = more reliable)."""
    BEHAVIORAL = 10    # Response difference, status code change
    TIMING = 20        # Time-based detection (blind SQLi sleep)
    REGEX_CANARY = 30  # Regex pattern match (e.g., /etc/passwd content)
    EXACT_MATCH = 40   # Exact canary string match
    DATA_EXFIL = 50    # Extracted sensitive data (cloud creds, file contents)


@dataclass
class EvidenceItem:
    """A single piece of evidence with type and details."""
    evidence_type: EvidenceType
    description: str
    confidence: float  # 0.0 - 1.0
    raw_data: str = ""


@dataclass
class ScoredFinding:
    """A finding enriched with evidence quality score."""
    finding: Finding
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    total_score: float = 0.0
    confidence: float = 0.0  # 0.0 - 1.0

    @property
    def quality_label(self) -> str:
        """Human-readable quality label."""
        if self.confidence >= 0.9:
            return "confirmed"
        if self.confidence >= 0.7:
            return "high-confidence"
        if self.confidence >= 0.5:
            return "likely"
        if self.confidence >= 0.3:
            return "possible"
        return "unconfirmed"


# Weight multipliers for evidence types
_WEIGHTS: Dict[EvidenceType, float] = {
    EvidenceType.BEHAVIORAL: 1.0,
    EvidenceType.TIMING: 2.0,
    EvidenceType.REGEX_CANARY: 3.0,
    EvidenceType.EXACT_MATCH: 4.0,
    EvidenceType.DATA_EXFIL: 5.0,
}

# Severity multipliers for confidence adjustment
_SEVERITY_THRESHOLDS: Dict[Severity, float] = {
    Severity.CRITICAL: 0.3,   # lower threshold to confirm critical
    Severity.HIGH: 0.4,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.6,
    Severity.INFO: 0.8,
}


class EvidenceScorer:
    """
    Score and rank findings by evidence quality:
      1. Calculate weighted score from evidence items
      2. Classify as confirmed / high-confidence / likely / possible
      3. Filter findings below confidence threshold
      4. Rank findings for prioritized reporting
    """

    def __init__(
        self,
        *,
        min_confidence: float = 0.3,
        weights: Optional[Dict[EvidenceType, float]] = None,
    ) -> None:
        self._min_confidence = min_confidence
        self._weights = weights or _WEIGHTS

    def score_finding(
        self,
        finding: Finding,
        evidence_items: List[EvidenceItem],
    ) -> ScoredFinding:
        """
        Calculate quality score for a finding based on its evidence.

        Args:
            finding: The original finding.
            evidence_items: List of evidence items supporting the finding.

        Returns:
            ScoredFinding with calculated score and confidence.
        """
        if not evidence_items:
            return ScoredFinding(
                finding=finding,
                evidence_items=[],
                total_score=0.0,
                confidence=0.0,
            )

        # Calculate weighted score
        total_weight = 0.0
        weighted_confidence_sum = 0.0

        for item in evidence_items:
            weight = self._weights.get(item.evidence_type, 1.0)
            total_weight += weight
            weighted_confidence_sum += weight * item.confidence

        # Average weighted confidence
        confidence = weighted_confidence_sum / total_weight if total_weight > 0 else 0.0

        # Bonus for multiple independent evidence types
        unique_types = len(set(item.evidence_type for item in evidence_items))
        if unique_types >= 3:
            confidence = min(1.0, confidence * 1.2)
        elif unique_types >= 2:
            confidence = min(1.0, confidence * 1.1)

        # Score = sum of individual scores
        total_score = sum(
            self._weights.get(item.evidence_type, 1.0) * item.confidence
            for item in evidence_items
        )

        return ScoredFinding(
            finding=finding,
            evidence_items=evidence_items,
            total_score=total_score,
            confidence=confidence,
        )

    def rank_findings(
        self,
        scored_findings: List[ScoredFinding],
    ) -> List[ScoredFinding]:
        """
        Rank findings by evidence quality and severity.

        Returns findings sorted by:
        1. Confidence (descending)
        2. Severity (descending)
        3. Total score (descending)
        """
        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }

        return sorted(
            scored_findings,
            key=lambda sf: (
                sf.confidence,
                severity_order.get(sf.finding.severity, 0),
                sf.total_score,
            ),
            reverse=True,
        )

    def filter_by_confidence(
        self,
        scored_findings: List[ScoredFinding],
        min_confidence: Optional[float] = None,
    ) -> List[ScoredFinding]:
        """Filter findings below the minimum confidence threshold."""
        threshold = min_confidence if min_confidence is not None else self._min_confidence
        return [sf for sf in scored_findings if sf.confidence >= threshold]

    def classify_evidence(
        self,
        finding: Finding,
    ) -> List[EvidenceItem]:
        """
        Auto-classify evidence from a finding's evidence string.
        Useful for retroactively scoring findings from earlier phases.
        """
        items: List[EvidenceItem] = []
        evidence = finding.evidence or ""
        title = finding.title or ""
        tags = finding.tags or []

        # Check for exact match indicators
        if "[CONFIRMED]" in title:
            items.append(EvidenceItem(
                evidence_type=EvidenceType.EXACT_MATCH,
                description="Finding marked as confirmed",
                confidence=0.95,
                raw_data=title,
            ))

        # Check for data exfiltration evidence
        data_exfil_patterns = [
            (r"(AccessKeyId|SecretAccessKey)", "Cloud credentials extracted"),
            (r"root:[x*]:0:0:", "/etc/passwd contents extracted"),
            (r"\[(fonts|extensions|mci)\]", "win.ini contents extracted"),
        ]
        for pattern, desc in data_exfil_patterns:
            if re.search(pattern, evidence, re.IGNORECASE):
                items.append(EvidenceItem(
                    evidence_type=EvidenceType.DATA_EXFIL,
                    description=desc,
                    confidence=0.99,
                    raw_data=evidence[:200],
                ))
                break

        # Check for regex canary matches
        canary_indicators = [
            "canary match", "pattern match", "reflected",
            "response snippet", "Canary:",
        ]
        if any(ind in evidence.lower() for ind in canary_indicators):
            items.append(EvidenceItem(
                evidence_type=EvidenceType.REGEX_CANARY,
                description="Canary pattern detected in evidence",
                confidence=0.8,
                raw_data=evidence[:200],
            ))

        # Check for timing evidence
        timing_patterns = [
            (r"response time:\s*([\d.]+)s", "Timing anomaly"),
            (r"delay.*?([\d.]+)\s*s", "Measured delay"),
            (r"elapsed.*?([\d.]+)", "Elapsed time measurement"),
        ]
        for pattern, desc in timing_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                try:
                    delay = float(match.group(1))
                    confidence = min(0.9, delay / 10.0) if delay > 1.0 else 0.3
                    items.append(EvidenceItem(
                        evidence_type=EvidenceType.TIMING,
                        description=f"{desc}: {delay:.1f}s",
                        confidence=confidence,
                        raw_data=match.group(0),
                    ))
                except ValueError:
                    pass
                break

        # Check for behavioral evidence
        behavioral_indicators = [
            "status code", "different response", "server error",
            "500", "crash", "accepted",
        ]
        if not items and any(ind in evidence.lower() for ind in behavioral_indicators):
            items.append(EvidenceItem(
                evidence_type=EvidenceType.BEHAVIORAL,
                description="Behavioral anomaly detected",
                confidence=0.5,
                raw_data=evidence[:200],
            ))

        # Tag-based confidence boost
        if "confirmed" in tags:
            for item in items:
                item.confidence = min(1.0, item.confidence + 0.1)

        return items

    def auto_score(self, finding: Finding) -> ScoredFinding:
        """
        Convenience: auto-classify evidence and score in one step.
        """
        items = self.classify_evidence(finding)
        return self.score_finding(finding, items)

    def batch_score(self, findings: List[Finding]) -> List[ScoredFinding]:
        """Score, rank, and filter a batch of findings."""
        scored = [self.auto_score(f) for f in findings]
        filtered = self.filter_by_confidence(scored)
        return self.rank_findings(filtered)
