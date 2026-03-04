"""Scan state persistence — save / load mid-run, resume from checkpoint.

Phase 4 item #64.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.core.scan_persistence")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class CheckpointMeta:
    """Metadata about a saved checkpoint."""
    scan_id: str
    created_at: str
    modules_completed: List[str] = field(default_factory=list)
    modules_pending: List[str] = field(default_factory=list)
    total_findings: int = 0
    total_targets: int = 0
    version: str = "1.0"


@dataclass
class ScanCheckpoint:
    """Full checkpoint — everything needed to resume a scan."""
    meta: CheckpointMeta
    targets: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    module_states: Dict[str, str] = field(default_factory=dict)


class ScanPersistence:
    """Save and load scan state for checkpoint / resume support.

    Use cases:
    - Long-running scans that may be interrupted
    - CI/CD time limits — save partial results, resume in next run
    - Manual pause/resume by the operator
    - Crash recovery — auto-save periodic checkpoints
    """

    DEFAULT_DIR = ".krumpa_checkpoints"

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        auto_save_interval: int = 300,  # seconds
    ) -> None:
        self._checkpoint_dir = Path(checkpoint_dir or self.DEFAULT_DIR)
        self._auto_save_interval = auto_save_interval
        self._last_save_time: float = 0.0

    # ----------------------------------------------------------
    # Save
    # ----------------------------------------------------------

    def save(
        self,
        ctx: ScanContext,
        modules_completed: Optional[List[str]] = None,
        modules_pending: Optional[List[str]] = None,
    ) -> str:
        """Save the current scan state to a checkpoint file.

        Returns the path to the saved checkpoint.
        """
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)

        meta = CheckpointMeta(
            scan_id=ctx.scan_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            modules_completed=modules_completed or [],
            modules_pending=modules_pending or [],
            total_findings=len(ctx.findings),
            total_targets=len(ctx.targets),
        )

        checkpoint = ScanCheckpoint(
            meta=meta,
            targets=[self._target_to_dict(t) for t in ctx.targets],
            findings=[f.to_dict() for f in ctx.findings],
            config=dict(ctx.config),
            auth_tokens=dict(ctx.auth_tokens),
            metadata={
                k: v for k, v in ctx.metadata.items()
                if self._is_serializable(v)
            },
        )

        filename = f"checkpoint_{ctx.scan_id}_{int(time.time())}.json"
        filepath = self._checkpoint_dir / filename

        data = self._checkpoint_to_dict(checkpoint)
        filepath.write_text(json.dumps(data, indent=2, default=str))
        self._last_save_time = time.time()

        logger.info("Checkpoint saved: %s (%d findings, %d targets)",
                     filepath, meta.total_findings, meta.total_targets)
        return str(filepath)

    def auto_save(
        self,
        ctx: ScanContext,
        modules_completed: Optional[List[str]] = None,
        modules_pending: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Save only if enough time has elapsed since last save."""
        elapsed = time.time() - self._last_save_time
        if elapsed >= self._auto_save_interval:
            return self.save(ctx, modules_completed, modules_pending)
        return None

    # ----------------------------------------------------------
    # Load
    # ----------------------------------------------------------

    def load(self, filepath: str) -> ScanCheckpoint:
        """Load a checkpoint from a file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {filepath}")

        data = json.loads(path.read_text())
        return self._dict_to_checkpoint(data)

    def load_latest(self, scan_id: Optional[str] = None) -> Optional[ScanCheckpoint]:
        """Load the most recent checkpoint, optionally filtered by scan_id."""
        if not self._checkpoint_dir.exists():
            return None

        files = sorted(
            self._checkpoint_dir.glob("checkpoint_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        for f in files:
            try:
                cp = self.load(str(f))
                if scan_id is None or cp.meta.scan_id == scan_id:
                    return cp
            except Exception as exc:
                logger.warning("Failed to load checkpoint %s: %s", f, exc)
                continue

        return None

    def list_checkpoints(self) -> List[CheckpointMeta]:
        """List all available checkpoints."""
        results: List[CheckpointMeta] = []

        if not self._checkpoint_dir.exists():
            return results

        for f in sorted(
            self._checkpoint_dir.glob("checkpoint_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                data = json.loads(f.read_text())
                meta_data = data.get("meta", {})
                results.append(CheckpointMeta(
                    scan_id=meta_data.get("scan_id", ""),
                    created_at=meta_data.get("created_at", ""),
                    modules_completed=meta_data.get("modules_completed", []),
                    modules_pending=meta_data.get("modules_pending", []),
                    total_findings=meta_data.get("total_findings", 0),
                    total_targets=meta_data.get("total_targets", 0),
                    version=meta_data.get("version", "1.0"),
                ))
            except Exception:
                continue

        return results

    # ----------------------------------------------------------
    # Resume
    # ----------------------------------------------------------

    def restore_context(self, checkpoint: ScanCheckpoint) -> ScanContext:
        """Rebuild a ScanContext from a checkpoint."""
        ctx = ScanContext(
            scan_id=checkpoint.meta.scan_id,
            config=dict(checkpoint.config),
            auth_tokens=dict(checkpoint.auth_tokens),
            metadata=dict(checkpoint.metadata),
        )

        # Restore targets
        for t_dict in checkpoint.targets:
            ctx.targets.append(Target(
                url=t_dict.get("url", ""),
                method=t_dict.get("method", "GET"),
                headers=t_dict.get("headers", {}),
                body=t_dict.get("body"),
                metadata=t_dict.get("metadata", {}),
            ))

        # Restore findings
        for f_dict in checkpoint.findings:
            target = None
            if f_dict.get("target"):
                target = Target(url=f_dict["target"])

            ctx.findings.append(Finding(
                id=f_dict.get("id", ""),
                title=f_dict.get("title", ""),
                description=f_dict.get("description", ""),
                severity=Severity(f_dict.get("severity", "info")),
                module=f_dict.get("module", ""),
                target=target,
                evidence=f_dict.get("evidence", ""),
                remediation=f_dict.get("remediation", ""),
                cwe=f_dict.get("cwe"),
                cvss_score=f_dict.get("cvss_score"),
                tags=f_dict.get("tags", []),
            ))

        logger.info(
            "Context restored: scan_id=%s, %d targets, %d findings, "
            "completed=%s, pending=%s",
            ctx.scan_id, len(ctx.targets), len(ctx.findings),
            checkpoint.meta.modules_completed,
            checkpoint.meta.modules_pending,
        )
        return ctx

    # ----------------------------------------------------------
    # Cleanup
    # ----------------------------------------------------------

    def cleanup(
        self, scan_id: Optional[str] = None, keep_latest: int = 3,
    ) -> int:
        """Remove old checkpoints, keeping the N most recent."""
        if not self._checkpoint_dir.exists():
            return 0

        files = sorted(
            self._checkpoint_dir.glob("checkpoint_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if scan_id:
            matching = []
            other = []
            for f in files:
                try:
                    data = json.loads(f.read_text())
                    if data.get("meta", {}).get("scan_id") == scan_id:
                        matching.append(f)
                    else:
                        other.append(f)
                except Exception:
                    other.append(f)
            files = matching
        else:
            pass  # all files

        removed = 0
        for f in files[keep_latest:]:
            try:
                f.unlink()
                removed += 1
            except Exception as exc:
                logger.warning("Failed to remove checkpoint %s: %s", f, exc)

        return removed

    # ----------------------------------------------------------
    # Serialization helpers
    # ----------------------------------------------------------

    @staticmethod
    def _target_to_dict(target: Target) -> Dict[str, Any]:
        return {
            "url": target.url,
            "method": target.method,
            "headers": dict(target.headers),
            "body": target.body,
            "metadata": {
                k: v for k, v in target.metadata.items()
                if isinstance(v, (str, int, float, bool, list, dict, type(None)))
            },
        }

    @staticmethod
    def _checkpoint_to_dict(cp: ScanCheckpoint) -> Dict[str, Any]:
        return {
            "meta": {
                "scan_id": cp.meta.scan_id,
                "created_at": cp.meta.created_at,
                "modules_completed": cp.meta.modules_completed,
                "modules_pending": cp.meta.modules_pending,
                "total_findings": cp.meta.total_findings,
                "total_targets": cp.meta.total_targets,
                "version": cp.meta.version,
            },
            "targets": cp.targets,
            "findings": cp.findings,
            "config": cp.config,
            "auth_tokens": cp.auth_tokens,
            "metadata": cp.metadata,
            "module_states": cp.module_states,
        }

    @staticmethod
    def _dict_to_checkpoint(data: Dict[str, Any]) -> ScanCheckpoint:
        meta_data = data.get("meta", {})
        return ScanCheckpoint(
            meta=CheckpointMeta(
                scan_id=meta_data.get("scan_id", ""),
                created_at=meta_data.get("created_at", ""),
                modules_completed=meta_data.get("modules_completed", []),
                modules_pending=meta_data.get("modules_pending", []),
                total_findings=meta_data.get("total_findings", 0),
                total_targets=meta_data.get("total_targets", 0),
                version=meta_data.get("version", "1.0"),
            ),
            targets=data.get("targets", []),
            findings=data.get("findings", []),
            config=data.get("config", {}),
            auth_tokens=data.get("auth_tokens", {}),
            metadata=data.get("metadata", {}),
            module_states=data.get("module_states", {}),
        )

    @staticmethod
    def _is_serializable(value: Any) -> bool:
        """Check if a value can be JSON-serialized."""
        try:
            json.dumps(value, default=str)
            return True
        except (TypeError, ValueError):
            return False
