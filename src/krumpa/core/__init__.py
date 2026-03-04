"""
GateKrumpa core — shared primitives for all modules.

Provides:
    BaseModule      — abstract base every module inherits from
    Target          — canonical representation of a scan target
    Finding         — standardised vulnerability finding
    ScanContext     — runtime context / config bag passed to modules
    Severity        — CVSS-aligned severity enum
"""

from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(enum.Enum):
    """CVSS-aligned severity buckets."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModuleStatus(enum.Enum):
    """Lifecycle states for a running module."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Target:
    """A single scan target (URL, host, API endpoint, etc.)."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).hostname or self.url


@dataclass
class Finding:
    """A single security finding produced by any module."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    module: str = ""
    target: Optional[Target] = None
    evidence: str = ""
    remediation: str = ""
    cwe: Optional[int] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "module": self.module,
            "target": self.target.url if self.target else None,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanContext:
    """Runtime configuration & state bag available to every module."""
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    targets: List[Target] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    http_client: Any = None  # Optional[HttpClient] — lifecycle managed by ScanEngine
    _seen_finding_keys: set = field(default_factory=set, repr=False)

    def add_finding(self, finding: Finding) -> None:
        """Append a finding, deduplicating by (title, cwe, target url+method).

        If an identical key already exists the new finding is silently
        dropped so modules running in parallel don't bloat the report.
        """
        key = self.finding_key(finding)
        if key in self._seen_finding_keys:
            return
        self._seen_finding_keys.add(key)
        self.findings.append(finding)

    @staticmethod
    def finding_key(f: Finding) -> str:
        target_str = ""
        if f.target:
            target_str = f"{f.target.method}:{f.target.url}"
        return f"{f.title}|{f.severity.value}|{f.cwe or ''}|{target_str}"

    def add_target(self, target: Target) -> None:
        """Add a target, deduplicating by URL + method.

        If an existing target matches on ``(url, method)``, its metadata
        and headers are merged (new values win) rather than creating a
        duplicate entry.
        """
        for existing in self.targets:
            if existing.url == target.url and existing.method == target.method:
                existing.metadata.update(target.metadata)
                existing.headers.update(target.headers)
                if target.body and not existing.body:
                    existing.body = target.body
                return
        self.targets.append(target)

    def summary(self) -> Dict[str, Any]:
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "scan_id": self.scan_id,
            "total_targets": len(self.targets),
            "total_findings": len(self.findings),
            "findings_by_severity": by_sev,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }

    def clear_sensitive(self) -> None:
        """Wipe authentication tokens and other sensitive runtime data."""
        self.auth_tokens.clear()
        self.metadata.pop("cookies", None)
        self.metadata.pop("session", None)


# ---------------------------------------------------------------------------
# Abstract base module
# ---------------------------------------------------------------------------

class BaseModule(abc.ABC):
    """
    Every GateKrumpa module must inherit from ``BaseModule`` and implement
    at minimum ``run()``.
    """

    name: str = "unnamed"
    description: str = ""
    dependencies: List[str] = []  # module names that must complete before this one

    def __init__(self) -> None:
        self.status: ModuleStatus = ModuleStatus.IDLE
        self.findings: List[Finding] = []

    # -- lifecycle ----------------------------------------------------------

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> List[Finding]:
        """Execute the module against the given scan context."""
        ...

    async def setup(self, ctx: ScanContext) -> None:
        """Optional hook called before ``run``."""

    async def teardown(self, ctx: ScanContext) -> None:
        """Optional hook called after ``run``."""

    # -- helpers ------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        finding.module = self.name
        self.findings.append(finding)

    def reset(self) -> None:
        self.status = ModuleStatus.IDLE
        self.findings.clear()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} status={self.status.value}>"
