"""
WaaaghGate — Trend tracking.

Track historical scan results to identify trends:
- Finding count over time (total, by severity)
- New vs. resolved per scan
- Mean Time To Remediate (MTTR)
- Severity distribution shifts
- Regression rate

Stores history in a JSON file, one record per scan run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding

logger = logging.getLogger("krumpa.waaaghgate.trend_tracker")


@dataclass
class ScanRecord:
    """Summary of a single scan run."""
    scan_id: str
    timestamp: float
    total_findings: int
    by_severity: Dict[str, int] = field(default_factory=dict)
    new_findings: int = 0
    resolved_findings: int = 0
    reopened_findings: int = 0
    gate_passed: bool = True
    fingerprints: List[str] = field(default_factory=list)
    duration_seconds: Optional[float] = None


@dataclass
class TrendMetrics:
    """Computed trend metrics across scan history."""
    total_scans: int = 0
    finding_counts: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    mttr_seconds: Optional[float] = None  # mean time to remediate
    regression_rate: float = 0.0  # reopened / total resolved
    severity_trend: Dict[str, List[int]] = field(default_factory=dict)
    gate_pass_rate: float = 0.0


class TrendTracker:
    """
    Track scan results over time and compute trend metrics.

    Features:
    - Record each scan run's summary
    - Compute MTTR (mean time from first-seen to resolved)
    - Track severity distribution over time
    - Detect trends (improving, worsening, stable)
    - JSON persistence
    """

    def __init__(self, *, history_file: Optional[str] = None) -> None:
        self._history_file = Path(history_file) if history_file else None
        self._records: List[ScanRecord] = []
        self._resolved_times: Dict[str, float] = {}  # fingerprint → first_seen
        self._first_seen: Dict[str, float] = {}  # fingerprint → first_seen

    def load(self, path: Optional[str] = None) -> None:
        """Load scan history from JSON."""
        p = Path(path) if path else self._history_file
        if not p or not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            records = data.get("records", [])
            self._records = [ScanRecord(**r) for r in records]
            self._first_seen = data.get("first_seen", {})
            self._resolved_times = data.get("resolved_times", {})
            logger.info("Loaded %d scan records from %s", len(self._records), p)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.warning("Failed to load trend history: %s", exc)

    def save(self, path: Optional[str] = None) -> None:
        """Persist scan history to JSON."""
        p = Path(path) if path else self._history_file
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "records": [asdict(r) for r in self._records],
            "first_seen": self._first_seen,
            "resolved_times": self._resolved_times,
        }
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Saved %d scan records to %s", len(self._records), p)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_scan(
        self,
        findings: List[Finding],
        *,
        scan_id: str = "",
        gate_passed: bool = True,
        duration: Optional[float] = None,
    ) -> ScanRecord:
        """
        Record a scan run and compute deltas against previous run.

        Returns the ScanRecord that was stored.
        """
        now = time.time()
        if not scan_id:
            scan_id = f"scan-{int(now)}"

        # Compute severity counts
        by_severity: Dict[str, int] = {}
        current_fps: Set[str] = set()
        for f in findings:
            key = f.severity.name.lower()
            by_severity[key] = by_severity.get(key, 0) + 1
            fp = self._fingerprint(f)
            current_fps.add(fp)
            if fp not in self._first_seen:
                self._first_seen[fp] = now

        # Compare against previous scan
        prev_fps: Set[str] = set()
        if self._records:
            prev_fps = set(self._records[-1].fingerprints)

        new_fps = current_fps - prev_fps
        resolved_fps = prev_fps - current_fps
        reopened: Set[str] = set()

        # Track resolved times for MTTR
        for fp in resolved_fps:
            if fp in self._first_seen:
                self._resolved_times[fp] = now - self._first_seen[fp]

        # Detect reopened (was in resolved_times but now back)
        for fp in new_fps:
            if fp in self._resolved_times:
                reopened.add(fp)

        record = ScanRecord(
            scan_id=scan_id,
            timestamp=now,
            total_findings=len(findings),
            by_severity=by_severity,
            new_findings=len(new_fps - reopened),
            resolved_findings=len(resolved_fps),
            reopened_findings=len(reopened),
            gate_passed=gate_passed,
            fingerprints=sorted(current_fps),
            duration_seconds=duration,
        )
        self._records.append(record)

        logger.info(
            "Recorded scan %s: %d findings (%d new, %d resolved, %d reopened)",
            scan_id, record.total_findings, record.new_findings,
            record.resolved_findings, record.reopened_findings,
        )

        return record

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def compute_metrics(self) -> TrendMetrics:
        """Compute trend metrics across all recorded scans."""
        metrics = TrendMetrics(total_scans=len(self._records))

        if not self._records:
            return metrics

        metrics.finding_counts = [r.total_findings for r in self._records]
        metrics.timestamps = [r.timestamp for r in self._records]

        # MTTR
        if self._resolved_times:
            times = list(self._resolved_times.values())
            metrics.mttr_seconds = sum(times) / len(times)

        # Regression rate
        total_resolved = sum(r.resolved_findings for r in self._records)
        total_reopened = sum(r.reopened_findings for r in self._records)
        if total_resolved > 0:
            metrics.regression_rate = total_reopened / total_resolved

        # Gate pass rate
        passed = sum(1 for r in self._records if r.gate_passed)
        metrics.gate_pass_rate = passed / len(self._records)

        # Severity trends
        severity_keys = {"critical", "high", "medium", "low", "info"}
        for key in severity_keys:
            metrics.severity_trend[key] = [
                r.by_severity.get(key, 0) for r in self._records
            ]

        return metrics

    def trend_direction(self) -> str:
        """
        Determine overall trend direction.

        Returns: "improving", "worsening", or "stable"
        """
        if len(self._records) < 2:
            return "stable"

        recent = self._records[-3:]  # last 3 scans
        counts = [r.total_findings for r in recent]

        if len(counts) < 2:
            return "stable"

        # Simple linear trend
        if all(counts[i] <= counts[i - 1] for i in range(1, len(counts))):
            return "improving"
        if all(counts[i] >= counts[i - 1] for i in range(1, len(counts))):
            return "worsening"
        return "stable"

    def summary(self) -> Dict[str, Any]:
        """Human-readable summary of trend data."""
        metrics = self.compute_metrics()
        direction = self.trend_direction()

        result: Dict[str, Any] = {
            "total_scans": metrics.total_scans,
            "trend_direction": direction,
            "gate_pass_rate": f"{metrics.gate_pass_rate:.0%}",
            "regression_rate": f"{metrics.regression_rate:.0%}",
        }

        if metrics.mttr_seconds is not None:
            hours = metrics.mttr_seconds / 3600
            if hours < 1:
                result["mttr"] = f"{metrics.mttr_seconds / 60:.0f} minutes"
            elif hours < 24:
                result["mttr"] = f"{hours:.1f} hours"
            else:
                result["mttr"] = f"{hours / 24:.1f} days"

        if metrics.finding_counts:
            result["latest_count"] = metrics.finding_counts[-1]
            if len(metrics.finding_counts) > 1:
                delta = metrics.finding_counts[-1] - metrics.finding_counts[-2]
                result["delta"] = f"{'+' if delta > 0 else ''}{delta}"

        return result

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
