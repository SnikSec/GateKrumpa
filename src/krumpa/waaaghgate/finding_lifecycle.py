"""
WaaaghGate — Finding lifecycle state management.

Track findings through their lifecycle:
  New → Open → Acknowledged → False-Positive → Resolved → Reopened

Provides:
- State transitions with validation
- Audit trail (who, when, why)
- Bulk state operations
- State persistence (JSON)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding

logger = logging.getLogger("krumpa.waaaghgate.finding_lifecycle")


class LifecycleState(Enum):
    """Finding lifecycle states."""
    NEW = "new"
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    REOPENED = "reopened"


# Valid state transitions
_TRANSITIONS: Dict[LifecycleState, Set[LifecycleState]] = {
    LifecycleState.NEW: {LifecycleState.OPEN, LifecycleState.FALSE_POSITIVE},
    LifecycleState.OPEN: {LifecycleState.ACKNOWLEDGED, LifecycleState.RESOLVED, LifecycleState.FALSE_POSITIVE},
    LifecycleState.ACKNOWLEDGED: {LifecycleState.RESOLVED, LifecycleState.FALSE_POSITIVE},
    LifecycleState.FALSE_POSITIVE: {LifecycleState.REOPENED},
    LifecycleState.RESOLVED: {LifecycleState.REOPENED},
    LifecycleState.REOPENED: {LifecycleState.OPEN, LifecycleState.RESOLVED, LifecycleState.FALSE_POSITIVE},
}


@dataclass
class StateTransition:
    """A single state transition in the audit trail."""
    from_state: str
    to_state: str
    timestamp: float
    actor: str = "system"
    reason: str = ""


@dataclass
class FindingState:
    """Lifecycle state for a single finding, keyed by fingerprint."""
    fingerprint: str
    finding_title: str
    current_state: str = "new"
    first_seen: float = 0.0
    last_seen: float = 0.0
    transitions: List[Dict[str, Any]] = field(default_factory=list)

    def add_transition(self, transition: StateTransition) -> None:
        self.transitions.append(asdict(transition))
        self.current_state = transition.to_state


class FindingLifecycleManager:
    """
    Manage finding lifecycle states across scan runs.

    Features:
    - Automatic state updates (new findings → NEW, re-seen → OPEN/REOPENED)
    - Manual state transitions with validation
    - Audit trail for each finding
    - JSON persistence
    """

    def __init__(self, *, state_file: Optional[str] = None) -> None:
        self._state_file = Path(state_file) if state_file else None
        self._states: Dict[str, FindingState] = {}

    def load(self, path: Optional[str] = None) -> None:
        """Load state from JSON file."""
        p = Path(path) if path else self._state_file
        if not p or not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in data:
                state = FindingState(**item)
                self._states[state.fingerprint] = state
            logger.info("Loaded %d finding states from %s", len(self._states), p)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.warning("Failed to load lifecycle state: %s", exc)

    def save(self, path: Optional[str] = None) -> None:
        """Persist state to JSON file."""
        p = Path(path) if path else self._state_file
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(s) for s in self._states.values()]
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Saved %d finding states to %s", len(data), p)

    # ------------------------------------------------------------------
    # Automatic state management
    # ------------------------------------------------------------------

    def process_scan_results(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """
        Process findings from a scan run and update lifecycle states.

        Returns a dict with lists of fingerprints in each category:
        - "new": First-time findings
        - "recurring": Previously seen, still present
        - "resolved": Previously seen, now absent
        - "reopened": Was resolved/FP, now seen again
        """
        now = time.time()
        current_fps: Set[str] = set()
        result: Dict[str, List[str]] = {
            "new": [], "recurring": [], "resolved": [], "reopened": [],
        }

        for finding in findings:
            fp = self._fingerprint(finding)
            current_fps.add(fp)

            if fp not in self._states:
                # Brand new finding
                self._states[fp] = FindingState(
                    fingerprint=fp,
                    finding_title=finding.title,
                    current_state=LifecycleState.NEW.value,
                    first_seen=now,
                    last_seen=now,
                )
                result["new"].append(fp)
            else:
                state = self._states[fp]
                state.last_seen = now

                if state.current_state in (
                    LifecycleState.RESOLVED.value,
                    LifecycleState.FALSE_POSITIVE.value,
                ):
                    # Was resolved/FP but reappeared → reopen
                    self._transition(
                        fp, LifecycleState.REOPENED,
                        actor="scan", reason="finding reappeared in scan",
                    )
                    result["reopened"].append(fp)
                elif state.current_state == LifecycleState.NEW.value:
                    # Second scan → promote to OPEN
                    self._transition(
                        fp, LifecycleState.OPEN,
                        actor="scan", reason="confirmed in subsequent scan",
                    )
                    result["recurring"].append(fp)
                else:
                    result["recurring"].append(fp)

        # Mark absent findings as resolved (if they were OPEN/ACKNOWLEDGED)
        for fp, state in self._states.items():
            if fp not in current_fps:
                if state.current_state in (
                    LifecycleState.OPEN.value,
                    LifecycleState.ACKNOWLEDGED.value,
                    LifecycleState.NEW.value,
                    LifecycleState.REOPENED.value,
                ):
                    self._transition(
                        fp, LifecycleState.RESOLVED,
                        actor="scan", reason="not found in latest scan",
                    )
                    result["resolved"].append(fp)

        logger.info(
            "Lifecycle update: %d new, %d recurring, %d resolved, %d reopened",
            len(result["new"]), len(result["recurring"]),
            len(result["resolved"]), len(result["reopened"]),
        )

        return result

    # ------------------------------------------------------------------
    # Manual transitions
    # ------------------------------------------------------------------

    def transition(
        self,
        fingerprint: str,
        to_state: LifecycleState,
        *,
        actor: str = "user",
        reason: str = "",
    ) -> bool:
        """
        Manually transition a finding to a new state.

        Returns True if transition was valid and applied.
        """
        return self._transition(fingerprint, to_state, actor=actor, reason=reason)

    def _transition(
        self,
        fingerprint: str,
        to_state: LifecycleState,
        *,
        actor: str = "system",
        reason: str = "",
    ) -> bool:
        """Apply a state transition with validation."""
        state = self._states.get(fingerprint)
        if not state:
            logger.warning("No state for fingerprint %s", fingerprint)
            return False

        current = LifecycleState(state.current_state)
        valid_targets = _TRANSITIONS.get(current, set())

        if to_state not in valid_targets:
            logger.warning(
                "Invalid transition: %s → %s for %s",
                current.value, to_state.value, fingerprint,
            )
            return False

        transition = StateTransition(
            from_state=current.value,
            to_state=to_state.value,
            timestamp=time.time(),
            actor=actor,
            reason=reason,
        )
        state.add_transition(transition)
        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_state(self, fingerprint: str) -> Optional[FindingState]:
        """Get the lifecycle state for a finding."""
        return self._states.get(fingerprint)

    def get_by_state(self, state: LifecycleState) -> List[FindingState]:
        """Get all findings in a given state."""
        return [s for s in self._states.values() if s.current_state == state.value]

    def get_active(self) -> List[FindingState]:
        """Get all findings that are still active (not resolved/FP)."""
        inactive = {LifecycleState.RESOLVED.value, LifecycleState.FALSE_POSITIVE.value}
        return [s for s in self._states.values() if s.current_state not in inactive]

    def summary(self) -> Dict[str, int]:
        """Count findings by state."""
        counts: Dict[str, int] = {}
        for s in self._states.values():
            counts[s.current_state] = counts.get(s.current_state, 0) + 1
        return counts

    @property
    def total(self) -> int:
        return len(self._states)

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def bulk_transition(
        self,
        fingerprints: List[str],
        to_state: LifecycleState,
        *,
        actor: str = "user",
        reason: str = "",
    ) -> Dict[str, bool]:
        """Transition multiple findings. Returns success map."""
        return {
            fp: self._transition(fp, to_state, actor=actor, reason=reason)
            for fp in fingerprints
        }

    def bulk_false_positive(
        self,
        fingerprints: List[str],
        *,
        actor: str = "user",
        reason: str = "marked as false positive",
    ) -> Dict[str, bool]:
        """Mark multiple findings as false positive."""
        return self.bulk_transition(
            fingerprints, LifecycleState.FALSE_POSITIVE,
            actor=actor, reason=reason,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        """Generate a stable fingerprint for a finding."""
        import hashlib
        target_url = finding.target.url if finding.target else ""
        raw = f"{finding.title}|{target_url}|{finding.cwe}|{','.join(sorted(finding.tags))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
