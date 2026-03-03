"""Concurrent scan isolation — multiple scans with separate contexts.

Phase 4 item #65.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Target

logger = logging.getLogger("krumpa.core.scan_isolation")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class IsolatedScan:
    """A single isolated scan instance with its own context."""
    scan_id: str
    context: ScanContext
    status: str = "pending"  # pending, running, completed, failed, cancelled
    error: Optional[str] = None
    findings_count: int = 0


@dataclass
class RateLimitPool:
    """Per-scan rate limit configuration."""
    scan_id: str
    max_rps: float = 10.0      # requests per second
    max_concurrent: int = 5     # max concurrent connections
    burst: int = 20             # burst allowance
    _tokens: float = 0.0
    _last_refill: float = 0.0

    def try_acquire(self, now: float) -> bool:
        """Try to acquire a rate-limit token (token-bucket algorithm)."""
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.max_rps)
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


@dataclass
class ScanIsolationConfig:
    """Configuration for scan isolation."""
    max_concurrent_scans: int = 5
    default_max_rps: float = 10.0
    default_max_concurrent: int = 5
    isolate_findings: bool = True
    isolate_rate_limits: bool = True


class ScanIsolationManager:
    """Manage multiple concurrent scans with isolated contexts.

    Each scan gets:
    - Its own ScanContext (targets, findings, config)
    - Its own rate-limit pool (so scans don't starve each other)
    - Isolated findings (no cross-contamination between scans)
    - Independent lifecycle management

    This enables:
    - Multi-tenant scanning (different teams running scans simultaneously)
    - Parallel scans against different targets
    - A/B testing of scan configurations
    - Background continuous scanning alongside ad-hoc scans
    """

    def __init__(
        self, config: Optional[ScanIsolationConfig] = None,
    ) -> None:
        self._config = config or ScanIsolationConfig()
        self._scans: Dict[str, IsolatedScan] = {}
        self._rate_pools: Dict[str, RateLimitPool] = {}
        self._lock = asyncio.Lock()

    # ----------------------------------------------------------
    # Scan lifecycle
    # ----------------------------------------------------------

    async def create_scan(
        self,
        targets: Optional[List[Target]] = None,
        config: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
        max_rps: Optional[float] = None,
    ) -> IsolatedScan:
        """Create a new isolated scan."""
        async with self._lock:
            active = sum(
                1 for s in self._scans.values()
                if s.status in ("pending", "running")
            )
            if active >= self._config.max_concurrent_scans:
                raise RuntimeError(
                    f"Maximum concurrent scans ({self._config.max_concurrent_scans}) "
                    f"reached. Wait for existing scans to complete."
                )

            sid = scan_id or uuid.uuid4().hex[:16]

            ctx = ScanContext(
                scan_id=sid,
                targets=list(targets or []),
                config=dict(config or {}),
            )

            scan = IsolatedScan(scan_id=sid, context=ctx)
            self._scans[sid] = scan

            # Create rate-limit pool
            self._rate_pools[sid] = RateLimitPool(
                scan_id=sid,
                max_rps=max_rps or self._config.default_max_rps,
                max_concurrent=self._config.default_max_concurrent,
            )

            logger.info("Created isolated scan: %s (%d targets)",
                        sid, len(ctx.targets))
            return scan

    async def start_scan(
        self,
        scan_id: str,
        runner: Callable[[ScanContext], Any],
    ) -> IsolatedScan:
        """Start a scan using the provided runner function."""
        scan = self._get_scan(scan_id)
        if scan.status != "pending":
            raise RuntimeError(
                f"Scan {scan_id} is {scan.status}, cannot start"
            )

        scan.status = "running"
        try:
            _result = await runner(scan.context)
            scan.status = "completed"
            scan.findings_count = len(scan.context.findings)
            logger.info(
                "Scan %s completed: %d findings",
                scan_id, scan.findings_count,
            )
        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)[:500]
            logger.error("Scan %s failed: %s", scan_id, exc)
            raise

        return scan

    async def cancel_scan(self, scan_id: str) -> None:
        """Cancel a running scan."""
        scan = self._get_scan(scan_id)
        if scan.status in ("completed", "failed", "cancelled"):
            return
        scan.status = "cancelled"
        logger.info("Scan %s cancelled", scan_id)

    # ----------------------------------------------------------
    # Context access
    # ----------------------------------------------------------

    def get_context(self, scan_id: str) -> ScanContext:
        """Get the isolated context for a scan."""
        return self._get_scan(scan_id).context

    def get_findings(self, scan_id: str) -> List[Finding]:
        """Get findings for a specific scan."""
        return list(self._get_scan(scan_id).context.findings)

    def get_all_findings(self) -> Dict[str, List[Finding]]:
        """Get findings from all scans, keyed by scan_id."""
        return {
            sid: list(scan.context.findings)
            for sid, scan in self._scans.items()
        }

    def merge_findings(self, scan_ids: Optional[List[str]] = None) -> List[Finding]:
        """Merge findings from multiple scans into a single list.

        Deduplicates by (title, severity, cwe, target).
        """
        all_findings: List[Finding] = []
        seen_keys: set[str] = set()

        ids = scan_ids or list(self._scans.keys())
        for sid in ids:
            scan = self._scans.get(sid)
            if not scan:
                continue
            for f in scan.context.findings:
                key = ScanContext._finding_key(f)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_findings.append(f)

        return all_findings

    # ----------------------------------------------------------
    # Rate limiting
    # ----------------------------------------------------------

    def get_rate_pool(self, scan_id: str) -> RateLimitPool:
        """Get the rate-limit pool for a scan."""
        pool = self._rate_pools.get(scan_id)
        if not pool:
            raise KeyError(f"No rate pool for scan {scan_id}")
        return pool

    def update_rate_limit(
        self, scan_id: str, max_rps: Optional[float] = None,
        max_concurrent: Optional[int] = None,
    ) -> None:
        """Update rate limits for a scan."""
        pool = self.get_rate_pool(scan_id)
        if max_rps is not None:
            pool.max_rps = max_rps
        if max_concurrent is not None:
            pool.max_concurrent = max_concurrent

    # ----------------------------------------------------------
    # Status & monitoring
    # ----------------------------------------------------------

    def status(self, scan_id: str) -> Dict[str, Any]:
        """Get status info for a scan."""
        scan = self._get_scan(scan_id)
        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "findings_count": len(scan.context.findings),
            "targets_count": len(scan.context.targets),
            "error": scan.error,
        }

    def all_statuses(self) -> List[Dict[str, Any]]:
        """Get status for all scans."""
        return [self.status(sid) for sid in self._scans]

    # ----------------------------------------------------------
    # Cleanup
    # ----------------------------------------------------------

    async def cleanup_scan(self, scan_id: str) -> None:
        """Remove a completed/failed/cancelled scan and free resources."""
        async with self._lock:
            scan = self._scans.pop(scan_id, None)
            self._rate_pools.pop(scan_id, None)
            if scan:
                scan.context.clear_sensitive()
                logger.info("Cleaned up scan %s", scan_id)

    async def cleanup_completed(self) -> int:
        """Remove all completed/failed/cancelled scans."""
        to_remove = [
            sid for sid, s in self._scans.items()
            if s.status in ("completed", "failed", "cancelled")
        ]
        for sid in to_remove:
            await self.cleanup_scan(sid)
        return len(to_remove)

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    def _get_scan(self, scan_id: str) -> IsolatedScan:
        scan = self._scans.get(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        return scan
