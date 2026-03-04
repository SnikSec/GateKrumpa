"""
GateKrumpa core — scan orchestrator.

The ``ScanEngine`` drives the pipeline: it wires up modules, feeds them
the shared ``ScanContext``, and collects findings.

Key capabilities:
  - Topological ordering derived from module ``dependencies``
  - Parallel execution of independent modules via ``asyncio.gather``
  - Shared ``HttpClient`` lifecycle (create → inject → close)
  - Cascading cancellation when a dependency fails
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from krumpa.core import BaseModule, Finding, ModuleStatus, ScanContext
from krumpa.core.events import EventBus, ScanEvent

logger = logging.getLogger("krumpa.engine")


class ScanEngine:
    """Orchestrates module execution across a shared scan context."""

    def __init__(
        self,
        ctx: Optional[ScanContext] = None,
        *,
        http_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ctx = ctx or ScanContext()
        self._modules: Dict[str, BaseModule] = {}
        self._execution_order: List[str] = []
        self._http_config: Dict[str, Any] = http_config or {}
        self._event_bus: Optional[EventBus] = None

    # -- registration -------------------------------------------------------

    def register(self, module: BaseModule, *, order: Optional[int] = None) -> None:
        """Register a module instance.  Appended to execution order by default."""
        self._modules[module.name] = module
        if order is not None:
            self._execution_order.insert(order, module.name)
        else:
            self._execution_order.append(module.name)
        logger.info("Registered module: %s", module.name)

    def register_class(self, cls: Type[BaseModule], **kwargs) -> None:
        """Instantiate and register a module class."""
        self.register(cls(**kwargs))

    def set_event_bus(self, bus: EventBus) -> None:
        """Attach an event bus for lifecycle notifications."""
        self._event_bus = bus
        self.ctx.event_bus = bus

    # -- execution ----------------------------------------------------------

    async def run_all(self) -> ScanContext:
        """Run every registered module, respecting dependencies and parallelism.

        A shared ``HttpClient`` is created from *http_config*, injected
        into ``ctx.http_client``, and closed in a ``finally`` block.
        Modules at the same dependency level are executed concurrently.
        """
        from krumpa.core.http_client import HttpClient

        client = HttpClient(**self._http_config)
        self.ctx.http_client = client
        self.ctx.started_at = datetime.now(timezone.utc)
        logger.info(
            "Scan %s started — %d module(s)",
            self.ctx.scan_id,
            len(self._modules),
        )
        if self._event_bus:
            await self._event_bus.emit_async(ScanEvent.SCAN_STARTED, {
                "scan_id": self.ctx.scan_id,
                "target_count": len(self.ctx.targets),
            })

        try:
            levels = self._build_execution_levels()

            for level_names in levels:
                if len(level_names) == 1:
                    await self._run_module(self._modules[level_names[0]])
                else:
                    await asyncio.gather(
                        *(self._run_module(self._modules[n]) for n in level_names)
                    )
        finally:
            self.ctx.finished_at = datetime.now(timezone.utc)
            self.ctx.clear_sensitive()
            await client.close()
            self.ctx.http_client = None
            if self._event_bus:
                duration = None
                if self.ctx.started_at and self.ctx.finished_at:
                    duration = (self.ctx.finished_at - self.ctx.started_at).total_seconds()
                await self._event_bus.emit_async(ScanEvent.SCAN_FINISHED, {
                    "scan_id": self.ctx.scan_id,
                    "finding_count": len(self.ctx.findings),
                    "duration_s": duration,
                })

        logger.info(
            "Scan %s finished — %d finding(s)",
            self.ctx.scan_id,
            len(self.ctx.findings),
        )
        return self.ctx

    async def run_module(self, name: str) -> List[Finding]:
        """Run a single module by name (does **not** manage HttpClient)."""
        mod = self._modules[name]
        return await self._run_module(mod)

    async def _run_module(self, mod: BaseModule) -> List[Finding]:
        # -- dependency gate ------------------------------------------------
        for dep_name in mod.dependencies:
            if dep_name in self._modules:
                dep_mod = self._modules[dep_name]
                if dep_mod.status in (ModuleStatus.FAILED, ModuleStatus.CANCELLED):
                    logger.warning(
                        "Skipping module %s — dependency %s %s",
                        mod.name,
                        dep_name,
                        dep_mod.status.value,
                    )
                    mod.status = ModuleStatus.CANCELLED
                    if self._event_bus:
                        await self._event_bus.emit_async(ScanEvent.MODULE_SKIPPED, {
                            "module": mod.name,
                            "reason": f"dependency {dep_name} {dep_mod.status.value}",
                        })
                    return []

        logger.info("Running module: %s", mod.name)
        mod.status = ModuleStatus.RUNNING
        if self._event_bus:
            await self._event_bus.emit_async(ScanEvent.MODULE_STARTED, {"module": mod.name})
        try:
            await mod.setup(self.ctx)
            findings = await mod.run(self.ctx)
            mod.status = ModuleStatus.COMPLETED
            if self._event_bus:
                await self._event_bus.emit_async(ScanEvent.MODULE_COMPLETED, {
                    "module": mod.name,
                    "finding_count": len(findings),
                })
        except Exception as exc:
            mod.status = ModuleStatus.FAILED
            logger.error("Module %s failed: %s", mod.name, type(exc).__name__)
            logger.debug("Module %s traceback:", mod.name, exc_info=True)
            if self._event_bus:
                await self._event_bus.emit_async(ScanEvent.MODULE_FAILED, {
                    "module": mod.name,
                    "error": str(exc),
                })
            findings = []
        finally:
            await mod.teardown(self.ctx)

        for f in findings:
            self.ctx.add_finding(f)
        return findings

    # -- dependency graph ---------------------------------------------------

    def _topological_sort(self) -> List[str]:
        """Kahn's algorithm — returns a deterministic topological ordering.

        Raises ``ValueError`` on dependency cycles.
        Missing (unregistered) dependencies are silently skipped with a
        warning.
        """
        registered = set(self._modules.keys())

        # in_degree[n] = number of registered deps that n still waits for
        in_degree: Dict[str, int] = {n: 0 for n in registered}
        # graph[dep] = list of modules that depend on dep
        dependants: Dict[str, List[str]] = {n: [] for n in registered}

        for name, mod in self._modules.items():
            for dep in mod.dependencies:
                if dep not in registered:
                    logger.warning(
                        "Module %s depends on unregistered module %s — "
                        "dependency ignored",
                        name,
                        dep,
                    )
                    continue
                in_degree[name] += 1
                dependants[dep].append(name)

        # Seed queue with modules that have no (registered) dependencies
        queue = sorted(n for n in registered if in_degree[n] == 0)
        result: List[str] = []

        while queue:
            node = queue.pop(0)
            result.append(node)
            for dep_of in sorted(dependants[node]):
                in_degree[dep_of] -= 1
                if in_degree[dep_of] == 0:
                    queue.append(dep_of)
            queue.sort()  # keep output deterministic among peers

        if len(result) != len(registered):
            cycle = registered - set(result)
            raise ValueError(f"Dependency cycle detected among modules: {cycle}")

        return result

    def _build_execution_levels(self) -> List[List[str]]:
        """Group modules into parallel execution levels.

        Modules whose registered dependencies are all satisfied at the
        same depth are placed in the same level and can run concurrently.
        """
        order = self._topological_sort()
        registered = set(self._modules.keys())

        # Compute depth: 0 for roots, 1 + max(dep depths) otherwise
        depth: Dict[str, int] = {}
        for name in order:
            mod = self._modules[name]
            dep_depths = [
                depth[d] for d in mod.dependencies
                if d in registered and d in depth
            ]
            depth[name] = (max(dep_depths) + 1) if dep_depths else 0

        # Bucket by depth, preserving topo-sort order within each bucket
        max_depth = max(depth.values()) if depth else 0
        levels: List[List[str]] = []
        for d in range(max_depth + 1):
            group = [n for n in order if depth.get(n) == d]
            if group:
                levels.append(group)
        return levels

    # -- introspection ------------------------------------------------------

    @property
    def modules(self) -> Dict[str, BaseModule]:
        return dict(self._modules)

    def status_report(self) -> Dict[str, str]:
        return {name: mod.status.value for name, mod in self._modules.items()}

