"""
WaaaghGate — scan baseline comparison.

Save, load, and diff scan results against a stored baseline to track
finding changes across runs:

* **New findings** — not in baseline (regressions)
* **Fixed findings** — in baseline but not in current scan
* **Unchanged findings** — present in both
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding

logger = logging.getLogger("krumpa.waaaghgate.baseline")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BaselineDiff:
    """Result of comparing current findings against a baseline."""
    new_findings: List[Finding] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Finding] = field(default_factory=list)
    baseline_count: int = 0
    current_count: int = 0

    @property
    def has_regressions(self) -> bool:
        return len(self.new_findings) > 0

    @property
    def has_fixes(self) -> bool:
        return len(self.fixed_findings) > 0

    def summary(self) -> str:
        return (
            f"Baseline: {self.baseline_count} → Current: {self.current_count} | "
            f"New: {len(self.new_findings)}, Fixed: {len(self.fixed_findings)}, "
            f"Unchanged: {len(self.unchanged_findings)}"
        )


@dataclass
class BaselineEntry:
    """Serialisable representation of a baseline finding."""
    fingerprint: str
    title: str
    severity: str
    target_url: str
    module: str
    cwe: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "target_url": self.target_url,
            "module": self.module,
            "cwe": self.cwe,
            "tags": self.tags,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineEntry":
        return cls(
            fingerprint=data["fingerprint"],
            title=data.get("title", ""),
            severity=data.get("severity", "info"),
            target_url=data.get("target_url", ""),
            module=data.get("module", ""),
            cwe=data.get("cwe"),
            tags=data.get("tags", []),
            first_seen=data.get("first_seen", ""),
        )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

class Baseline:
    """Save, load, and compare scan findings against a baseline.

    The baseline is stored as a JSON file containing fingerprinted
    finding summaries.
    """

    def __init__(self, *, path: Optional[str] = None) -> None:
        self._path = Path(path) if path else None
        self._entries: Dict[str, BaselineEntry] = {}

    @property
    def count(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint(finding: Finding) -> str:
        """Generate a stable fingerprint for a finding.

        The fingerprint is based on the finding's title, target URL,
        method, severity, and CWE — deliberately NOT the finding ID
        (which is random) so the same logical finding produces the
        same fingerprint across runs.
        """
        parts = [
            finding.title,
            finding.target.url if finding.target else "",
            finding.target.method if finding.target else "",
            finding.severity.value,
            str(finding.cwe or ""),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Building a baseline from findings
    # ------------------------------------------------------------------

    def build(self, findings: List[Finding]) -> None:
        """Build a baseline from the given findings."""
        now = datetime.now(timezone.utc).isoformat()
        self._entries.clear()
        for f in findings:
            fp = self.fingerprint(f)
            self._entries[fp] = BaselineEntry(
                fingerprint=fp,
                title=f.title,
                severity=f.severity.value,
                target_url=f.target.url if f.target else "",
                module=f.module,
                cwe=f.cwe,
                tags=list(f.tags),
                first_seen=now,
            )

    # ------------------------------------------------------------------
    # Save / Load
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """Serialise the baseline to JSON and return it.

        If *path* is given (or was set in the constructor), also write
        the JSON to disk.
        """
        out_path = Path(path) if path else self._path
        data = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self._entries),
            "findings": [e.to_dict() for e in self._entries.values()],
        }
        json_str = json.dumps(data, indent=2)

        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json_str, encoding="utf-8")
            logger.info("Saved baseline with %d findings to %s", len(self._entries), out_path)

        return json_str

    def load(self, path: Optional[str] = None, *, json_str: Optional[str] = None) -> None:
        """Load a baseline from a file or JSON string.

        Parameters
        ----------
        path:
            File path to read from.
        json_str:
            Raw JSON string (takes priority over *path*).
        """
        if json_str:
            raw = json_str
        else:
            load_path = Path(path) if path else self._path
            if not load_path or not load_path.exists():
                logger.warning("No baseline file found at %s", load_path)
                return
            raw = load_path.read_text(encoding="utf-8")

        data = json.loads(raw)
        self._entries.clear()
        for entry_dict in data.get("findings", []):
            entry = BaselineEntry.from_dict(entry_dict)
            self._entries[entry.fingerprint] = entry

        logger.info("Loaded baseline with %d findings", len(self._entries))

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compare(self, current_findings: List[Finding]) -> BaselineDiff:
        """Compare *current_findings* against the loaded baseline.

        Returns a :class:`BaselineDiff` with new, fixed, and unchanged
        categories.
        """
        current_fps: Dict[str, Finding] = {}
        for f in current_findings:
            fp = self.fingerprint(f)
            current_fps[fp] = f

        baseline_fps: Set[str] = set(self._entries.keys())
        current_fp_set: Set[str] = set(current_fps.keys())

        new_fps = current_fp_set - baseline_fps
        fixed_fps = baseline_fps - current_fp_set
        unchanged_fps = baseline_fps & current_fp_set

        return BaselineDiff(
            new_findings=[current_fps[fp] for fp in new_fps],
            fixed_findings=[
                self._entries[fp].to_dict() for fp in fixed_fps
            ],
            unchanged_findings=[current_fps[fp] for fp in unchanged_fps],
            baseline_count=len(baseline_fps),
            current_count=len(current_fp_set),
        )
