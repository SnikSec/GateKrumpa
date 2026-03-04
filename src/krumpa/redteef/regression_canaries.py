"""
RedTeef — Regression canaries.

Re-confirm findings on subsequent scans to track whether
vulnerabilities have been fixed, persist, or regress.

Provides:
- Canary storage (JSON) for previously confirmed findings
- Re-confirmation workflow — replay PoC → compare outcome
- Status tracking: confirmed → fixed | still-vulnerable | regressed
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.regression_canaries")


# ------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------

@dataclass
class CanaryRecord:
    """Persistent record of a confirmed finding's PoC details."""
    canary_id: str
    finding_title: str
    vuln_type: str
    target_url: str
    target_method: str
    inject_field: str
    payload: str
    expected_indicator: str  # string to search for in response
    first_seen: float  # epoch
    last_confirmed: float  # epoch
    confirmation_count: int = 1
    status: str = "confirmed"  # confirmed | fixed | regressed

    @property
    def fingerprint(self) -> str:
        """Stable fingerprint for deduplication."""
        raw = f"{self.target_url}|{self.target_method}|{self.inject_field}|{self.payload}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class ReconfirmResult:
    """Result of re-testing a canary."""
    canary: CanaryRecord
    still_vulnerable: bool
    evidence: str
    response_status: int = 0
    response_time: float = 0.0


class CanaryStore:
    """
    JSON-file-backed store for canary records.
    
    File format: list of serialised CanaryRecord dicts.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = Path(path) if path else None
        self._records: Dict[str, CanaryRecord] = {}

    def load(self, path: Optional[str] = None) -> None:
        """Load canaries from disk."""
        p = Path(path) if path else self._path
        if not p or not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in data:
                rec = CanaryRecord(**item)
                self._records[rec.canary_id] = rec
            logger.info("Loaded %d canaries from %s", len(self._records), p)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.warning("Failed to load canary file %s: %s", p, exc)

    def save(self, path: Optional[str] = None) -> None:
        """Persist canaries to disk."""
        p = Path(path) if path else self._path
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(rec) for rec in self._records.values()]
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Saved %d canaries to %s", len(data), p)

    def add(self, record: CanaryRecord) -> None:
        """Add or update a canary record."""
        existing = self._records.get(record.canary_id)
        if existing:
            existing.last_confirmed = record.last_confirmed
            existing.confirmation_count += 1
            existing.status = record.status
        else:
            self._records[record.canary_id] = record

    def get_all(self) -> List[CanaryRecord]:
        """Return all canary records."""
        return list(self._records.values())

    def get_by_status(self, status: str) -> List[CanaryRecord]:
        """Filter canaries by status."""
        return [r for r in self._records.values() if r.status == status]

    def update_status(self, canary_id: str, status: str) -> None:
        """Update a canary's status."""
        if canary_id in self._records:
            self._records[canary_id].status = status

    def summary(self) -> Dict[str, int]:
        """Counts by status."""
        counts: Dict[str, int] = {}
        for r in self._records.values():
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts


class RegressionCanaryChecker:
    """
    Re-confirm previously discovered vulnerabilities to track
    fix status across subsequent scan runs.

    Workflow:
    1. Load canaries from previous run
    2. Replay each canary's PoC against the target
    3. Compare response to expected indicator
    4. Update status: still-vulnerable → confirmed, not found → fixed
    5. Generate findings for regressions and persistent vulns
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        canary_file: Optional[str] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._store = CanaryStore(path=canary_file)

    def load_canaries(self, path: Optional[str] = None) -> None:
        """Load canary records from file."""
        self._store.load(path)

    def save_canaries(self, path: Optional[str] = None) -> None:
        """Persist canary records to file."""
        self._store.save(path)

    def register_finding(
        self,
        finding: Finding,
        *,
        payload: str = "",
        expected_indicator: str = "",
        inject_field: str = "",
    ) -> CanaryRecord:
        """
        Register a newly confirmed finding as a canary for future regression checks.
        """
        target = finding.target or Target(url="https://unknown")
        now = time.time()
        canary_id = hashlib.sha256(
            f"{target.url}|{target.method}|{inject_field}|{payload}".encode()
        ).hexdigest()[:16]

        record = CanaryRecord(
            canary_id=canary_id,
            finding_title=finding.title,
            vuln_type=self._infer_type(finding),
            target_url=target.url,
            target_method=target.method or "GET",
            inject_field=inject_field,
            payload=payload,
            expected_indicator=expected_indicator,
            first_seen=now,
            last_confirmed=now,
            status="confirmed",
        )
        self._store.add(record)
        return record

    async def reconfirm_all(self) -> List[Finding]:
        """
        Re-test all tracked canaries and return findings for
        regressions and persistent vulnerabilities.
        """
        findings: List[Finding] = []
        canaries = self._store.get_all()

        if not canaries:
            logger.info("No canaries to re-confirm")
            return findings

        logger.info("Re-confirming %d canaries", len(canaries))

        for canary in canaries:
            result = await self._reconfirm_single(canary)

            if result.still_vulnerable:
                if canary.status == "fixed":
                    # Was fixed, now regressed
                    canary.status = "regressed"
                    self._store.update_status(canary.canary_id, "regressed")
                    findings.append(self._build_regression_finding(canary, result))
                    logger.warning("REGRESSION: %s on %s", canary.finding_title, canary.target_url)
                else:
                    canary.status = "confirmed"
                    canary.last_confirmed = time.time()
                    canary.confirmation_count += 1
                    self._store.update_status(canary.canary_id, "confirmed")
                    findings.append(self._build_persistent_finding(canary, result))
            else:
                if canary.status in ("confirmed", "regressed"):
                    canary.status = "fixed"
                    self._store.update_status(canary.canary_id, "fixed")
                    logger.info("FIXED: %s on %s", canary.finding_title, canary.target_url)

        summary = self._store.summary()
        logger.info(
            "Regression check complete: %s",
            ", ".join(f"{k}={v}" for k, v in summary.items()),
        )

        return findings

    async def _reconfirm_single(self, canary: CanaryRecord) -> ReconfirmResult:
        """Replay a single canary's PoC and check the result."""
        if not self._client:
            return ReconfirmResult(
                canary=canary, still_vulnerable=False,
                evidence="no HTTP client available",
            )

        target_url = canary.target_url
        method = canary.target_method
        headers: Dict[str, str] = {}
        data: Optional[str] = None

        # Build the replay request
        if canary.inject_field and method.upper() == "GET":
            sep = "&" if "?" in target_url else "?"
            target_url = f"{target_url}{sep}{canary.inject_field}={canary.payload}"
        elif canary.inject_field:
            data = f"{canary.inject_field}={canary.payload}"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            if method.upper() in ("POST", "PUT", "PATCH"):
                data = canary.payload
            else:
                sep = "&" if "?" in target_url else "?"
                target_url = f"{target_url}{sep}q={canary.payload}"

        import time as _time
        start = _time.monotonic()

        try:
            resp = await self._client.request(method, target_url, headers=headers, body=data)
            elapsed = _time.monotonic() - start
            text = resp.text

            # Check for expected indicator
            still_vulnerable = False
            evidence = "indicator not found in response"

            if canary.expected_indicator:
                if canary.expected_indicator.lower() in text.lower():
                    still_vulnerable = True
                    idx = text.lower().find(canary.expected_indicator.lower())
                    start_idx = max(0, idx - 40)
                    end_idx = min(len(text), idx + len(canary.expected_indicator) + 40)
                    evidence = f"indicator found: ...{text[start_idx:end_idx]}..."

            return ReconfirmResult(
                canary=canary,
                still_vulnerable=still_vulnerable,
                evidence=evidence,
                response_status=resp.status_code,
                response_time=elapsed,
            )
        except Exception as exc:
            return ReconfirmResult(
                canary=canary, still_vulnerable=False,
                evidence=f"request failed: {exc}",
            )

    @staticmethod
    def _infer_type(finding: Finding) -> str:
        """Infer vuln type from finding tags/title."""
        type_keywords = [
            "sqli", "xss", "ssti", "cmdi", "ssrf", "xxe",
            "path-traversal", "open-redirect", "nosql", "deserialization",
        ]
        for kw in type_keywords:
            if kw in finding.tags or kw in finding.title.lower():
                return kw
        return "unknown"

    @staticmethod
    def _build_regression_finding(canary: CanaryRecord, result: ReconfirmResult) -> Finding:
        """Build a finding for a regressed vulnerability."""
        return Finding(
            title=f"[REGRESSION] {canary.finding_title}",
            description=(
                f"Previously fixed vulnerability has regressed on {canary.target_url}. "
                f"The {canary.vuln_type} vulnerability was first seen at "
                f"epoch {canary.first_seen:.0f} and was marked as fixed, but is now "
                f"confirmed again. Confirmed {canary.confirmation_count + 1} times total."
            ),
            severity=Severity.CRITICAL,  # regressions are always critical
            target=Target(url=canary.target_url, method=canary.target_method),
            evidence=result.evidence,
            remediation=(
                "This vulnerability was previously fixed but has reappeared. "
                "Check recent code changes for regressions. Add automated tests "
                "to prevent future regressions."
            ),
            cwe=0,
            tags=["regression", canary.vuln_type, "redteef", "canary"],
        )

    @staticmethod
    def _build_persistent_finding(canary: CanaryRecord, result: ReconfirmResult) -> Finding:
        """Build a finding for a persistently vulnerable endpoint."""
        return Finding(
            title=f"[PERSISTENT] {canary.finding_title}",
            description=(
                f"Vulnerability on {canary.target_url} remains unfixed. "
                f"The {canary.vuln_type} vulnerability has been confirmed "
                f"{canary.confirmation_count} times since epoch {canary.first_seen:.0f}."
            ),
            severity=Severity.HIGH,
            target=Target(url=canary.target_url, method=canary.target_method),
            evidence=result.evidence,
            remediation=(
                "This vulnerability has persisted across multiple scans. "
                "Prioritize remediation."
            ),
            cwe=0,
            tags=["persistent", canary.vuln_type, "redteef", "canary"],
        )
