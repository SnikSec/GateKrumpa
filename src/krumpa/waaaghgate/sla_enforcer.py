"""
WaaaghGate — SLA enforcement.

Define and enforce time-based SLAs (Service Level Agreements) for
vulnerability remediation. The quality gate fails if any finding
exceeds its SLA based on severity.

Default SLAs:
- Critical: 3 days
- High: 14 days
- Medium: 30 days
- Low: 90 days
- Info: no SLA

SLAs can be customised via configuration.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.waaaghgate.sla_enforcer")


# Default SLA deadlines in seconds
_DEFAULT_SLAS: Dict[Severity, float] = {
    Severity.CRITICAL: 3 * 86400,    # 3 days
    Severity.HIGH: 14 * 86400,       # 14 days
    Severity.MEDIUM: 30 * 86400,     # 30 days
    Severity.LOW: 90 * 86400,        # 90 days
    Severity.INFO: 0,                # no SLA
}


@dataclass
class SlaPolicy:
    """SLA policy — max seconds per severity before breach."""
    deadlines: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Fill in defaults for missing severities
        for sev, default_seconds in _DEFAULT_SLAS.items():
            key = sev.name.lower()
            if key not in self.deadlines:
                self.deadlines[key] = default_seconds

    def deadline_for(self, severity: Severity) -> float:
        """Get the SLA deadline in seconds for a severity level."""
        return self.deadlines.get(severity.name.lower(), 0)

    def deadline_days(self, severity: Severity) -> float:
        """Get the SLA deadline in days."""
        return self.deadline_for(severity) / 86400

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SlaPolicy":
        """
        Create from config dict.

        Accepts days as values:
        {"critical": 3, "high": 14, "medium": 30, "low": 90}
        """
        deadlines = {
            k.lower(): float(v) * 86400
            for k, v in data.items()
        }
        return cls(deadlines=deadlines)


@dataclass
class SlaBreachItem:
    """A single SLA breach."""
    finding_fingerprint: str
    finding_title: str
    severity: Severity
    first_seen: float  # epoch
    deadline_seconds: float
    elapsed_seconds: float
    overdue_seconds: float

    @property
    def overdue_days(self) -> float:
        return self.overdue_seconds / 86400

    @property
    def deadline_days(self) -> float:
        return self.deadline_seconds / 86400


@dataclass
class SlaReport:
    """Summary of SLA enforcement results."""
    total_checked: int = 0
    breaches: List[SlaBreachItem] = field(default_factory=list)
    within_sla: int = 0
    no_sla: int = 0  # findings with no SLA (e.g., INFO)

    @property
    def has_breaches(self) -> bool:
        return len(self.breaches) > 0

    @property
    def breach_count(self) -> int:
        return len(self.breaches)

    def breach_summary(self) -> Dict[str, int]:
        """Breaches by severity."""
        counts: Dict[str, int] = {}
        for b in self.breaches:
            key = b.severity.name.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts


class SlaEnforcer:
    """
    Enforce SLA deadlines on findings. The quality gate should fail
    if any finding exceeds its severity-based remediation deadline.

    Usage:
    1. Load first-seen timestamps (from lifecycle / trend tracker)
    2. Call `enforce()` with current findings
    3. Check `report.has_breaches` to determine gate outcome
    """

    def __init__(
        self,
        *,
        policy: Optional[SlaPolicy] = None,
        first_seen_times: Optional[Dict[str, float]] = None,
    ) -> None:
        self._policy = policy or SlaPolicy()
        self._first_seen: Dict[str, float] = first_seen_times or {}

    def set_first_seen(self, fingerprint: str, timestamp: float) -> None:
        """Record when a finding was first seen."""
        if fingerprint not in self._first_seen:
            self._first_seen[fingerprint] = timestamp

    def load_first_seen(self, data: Dict[str, float]) -> None:
        """Bulk load first-seen timestamps."""
        self._first_seen.update(data)

    def enforce(
        self,
        findings: List[Finding],
        *,
        now: Optional[float] = None,
    ) -> SlaReport:
        """
        Check all findings against SLA deadlines.

        Args:
            findings: Current active findings.
            now: Current time (epoch). Defaults to time.time().

        Returns:
            SlaReport with breach details.
        """
        if now is None:
            now = time.time()

        report = SlaReport()

        for finding in findings:
            report.total_checked += 1
            fp = self._fingerprint(finding)
            deadline = self._policy.deadline_for(finding.severity)

            if deadline <= 0:
                report.no_sla += 1
                continue

            first_seen = self._first_seen.get(fp)
            if first_seen is None:
                # First time seeing this — record it, within SLA by default
                self._first_seen[fp] = now
                report.within_sla += 1
                continue

            elapsed = now - first_seen
            if elapsed > deadline:
                overdue = elapsed - deadline
                report.breaches.append(SlaBreachItem(
                    finding_fingerprint=fp,
                    finding_title=finding.title,
                    severity=finding.severity,
                    first_seen=first_seen,
                    deadline_seconds=deadline,
                    elapsed_seconds=elapsed,
                    overdue_seconds=overdue,
                ))
                logger.warning(
                    "SLA BREACH: '%s' (%s) — %.1f days overdue",
                    finding.title, finding.severity.name, overdue / 86400,
                )
            else:
                report.within_sla += 1

        logger.info(
            "SLA enforcement: %d checked, %d breaches, %d within SLA, %d no SLA",
            report.total_checked, report.breach_count,
            report.within_sla, report.no_sla,
        )

        return report

    def gate_check(
        self,
        findings: List[Finding],
        *,
        block_on_breach: bool = True,
    ) -> bool:
        """
        Convenience method: return True if gate should pass.

        If block_on_breach is True, the gate fails on any SLA breach.
        """
        report = self.enforce(findings)
        if block_on_breach and report.has_breaches:
            return False
        return True

    def breach_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Generate new findings for each SLA breach.

        These can be added to the scan results to make breaches
        visible in reports.
        """
        report = self.enforce(findings)
        breach_findings: List[Finding] = []

        for breach in report.breaches:
            breach_findings.append(Finding(
                title=f"SLA breach: {breach.finding_title}",
                description=(
                    f"Finding '{breach.finding_title}' ({breach.severity.name}) "
                    f"has exceeded its SLA deadline of {breach.deadline_days:.0f} days. "
                    f"It is {breach.overdue_days:.1f} days overdue "
                    f"(first seen {breach.elapsed_seconds / 86400:.1f} days ago)."
                ),
                severity=Severity.HIGH,  # SLA breaches are always HIGH
                target=None,
                evidence=(
                    f"fingerprint={breach.finding_fingerprint}, "
                    f"deadline={breach.deadline_days:.0f}d, "
                    f"overdue={breach.overdue_days:.1f}d"
                ),
                remediation=(
                    f"Remediate '{breach.finding_title}' immediately — "
                    f"it has exceeded the {breach.severity.name} SLA of "
                    f"{breach.deadline_days:.0f} days."
                ),
                cwe=0,
                tags=["sla-breach", breach.severity.name.lower(), "waaaghgate"],
            ))

        return breach_findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        """Stable fingerprint for a finding."""
        import hashlib
        target_url = finding.target.url if finding.target else ""
        raw = f"{finding.title}|{target_url}|{finding.cwe}|{','.join(sorted(finding.tags))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
