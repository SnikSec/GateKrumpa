"""
WaaaghGate — quality-gate policy engine.

Evaluates scan findings against configurable thresholds and produces
a pass/fail verdict suitable for CI/CD pipelines.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity

logger = logging.getLogger("krumpa.waaaghgate.gate")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class PolicyViolation:
    """A single threshold breach."""
    severity: Severity
    count: int
    threshold: int
    message: str


@dataclass
class GateResult:
    """Outcome of the quality-gate evaluation."""
    passed: bool
    violations: List[PolicyViolation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    summary: str = ""

    @property
    def exit_code(self) -> int:
        """Return 0 for pass, 1 for fail."""
        return 0 if self.passed else 1


# ------------------------------------------------------------------
# GatePolicy
# ------------------------------------------------------------------

class GatePolicy:
    """
    Configurable severity-based quality gate.

    Parameters
    ----------
    fail_on:
        Maximum allowed findings *per severity*. If a severity count
        exceeds its threshold the gate **fails**.
        Example: ``{Severity.CRITICAL: 0, Severity.HIGH: 3}``
    warn_on:
        Same shape as *fail_on* but triggers warnings instead of failures.
    fail_on_total:
        Maximum allowed total findings regardless of severity.
    ignore_tags:
        Findings carrying any of these tags are excluded from evaluation.
    """

    def __init__(
        self,
        *,
        fail_on: Optional[Dict[Severity, int]] = None,
        warn_on: Optional[Dict[Severity, int]] = None,
        fail_on_total: Optional[int] = None,
        ignore_tags: Optional[List[str]] = None,
    ) -> None:
        self.fail_on = fail_on or {Severity.CRITICAL: 0, Severity.HIGH: 5}
        self.warn_on = warn_on or {}
        self.fail_on_total = fail_on_total
        self.ignore_tags = set(ignore_tags or [])

    def evaluate(self, findings: List[Finding]) -> GateResult:
        """Evaluate *findings* against the configured policy."""
        filtered = self._filter(findings)

        # Count by severity
        counts: Dict[Severity, int] = {}
        for f in filtered:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        violations: List[PolicyViolation] = []
        warnings: List[str] = []

        # Check per-severity fail thresholds
        for sev, threshold in self.fail_on.items():
            count = counts.get(sev, 0)
            if count > threshold:
                violations.append(PolicyViolation(
                    severity=sev,
                    count=count,
                    threshold=threshold,
                    message=f"{sev.value}: {count} findings (max {threshold})",
                ))

        # Check total threshold
        total = len(filtered)
        if self.fail_on_total is not None and total > self.fail_on_total:
            violations.append(PolicyViolation(
                severity=Severity.INFO,
                count=total,
                threshold=self.fail_on_total,
                message=f"Total: {total} findings (max {self.fail_on_total})",
            ))

        # Check per-severity warn thresholds
        for sev, threshold in self.warn_on.items():
            count = counts.get(sev, 0)
            if count > threshold:
                warnings.append(f"Warning: {sev.value} has {count} findings (warn threshold {threshold})")

        passed = len(violations) == 0
        summary_parts = [f"{sev.value}={counts.get(sev, 0)}" for sev in Severity]
        summary = f"Gate {'PASSED' if passed else 'FAILED'} — " + ", ".join(summary_parts)

        return GateResult(
            passed=passed,
            violations=violations,
            warnings=warnings,
            summary=summary,
        )

    def _filter(self, findings: List[Finding]) -> List[Finding]:
        """Exclude findings matching ignore_tags."""
        if not self.ignore_tags:
            return findings
        return [
            f for f in findings
            if not (set(f.tags) & self.ignore_tags)
        ]
