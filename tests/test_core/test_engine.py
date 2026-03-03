"""Tests for ScanEngine — registration, execution, error handling."""

from __future__ import annotations

from typing import List

import pytest

from krumpa.core import BaseModule, Finding, ModuleStatus, ScanContext, Severity
from krumpa.core.engine import ScanEngine


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class FakeModule(BaseModule):
    """Controllable module for engine tests."""

    def __init__(
        self,
        name: str = "fake",
        *,
        findings: List[Finding] | None = None,
        raise_on_run: Exception | None = None,
        raise_on_setup: Exception | None = None,
    ):
        super().__init__()
        self.name = name
        self._findings = findings or []
        self._raise_on_run = raise_on_run
        self._raise_on_setup = raise_on_setup
        self.run_count = 0

    async def run(self, ctx: ScanContext) -> List[Finding]:
        self.run_count += 1
        if self._raise_on_run:
            raise self._raise_on_run
        return list(self._findings)

    async def setup(self, ctx: ScanContext) -> None:
        if self._raise_on_setup:
            raise self._raise_on_setup


class OrderTracker(BaseModule):
    """Records the order in which modules run."""

    execution_log: list = []  # class-level shared log

    def __init__(self, name: str):
        super().__init__()
        self.name = name

    async def run(self, ctx: ScanContext) -> List[Finding]:
        OrderTracker.execution_log.append(self.name)
        return []


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------

class TestRegistration:

    def test_register_module(self):
        engine = ScanEngine()
        mod = FakeModule("alpha")
        engine.register(mod)
        assert "alpha" in engine.modules
        assert engine.modules["alpha"] is mod

    def test_register_with_order(self):
        engine = ScanEngine()
        engine.register(FakeModule("b"))
        engine.register(FakeModule("a"), order=0)
        # "a" should be first in the execution order
        assert engine._execution_order == ["a", "b"]

    def test_register_class(self):
        engine = ScanEngine()
        engine.register_class(FakeModule, name="from-class")
        assert "from-class" in engine.modules

    def test_register_multiple(self):
        engine = ScanEngine()
        engine.register(FakeModule("x"))
        engine.register(FakeModule("y"))
        engine.register(FakeModule("z"))
        assert list(engine.modules.keys()) == ["x", "y", "z"]


# ------------------------------------------------------------------
# Execution — run_all()
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestRunAll:

    async def test_run_all_returns_context(self):
        engine = ScanEngine()
        engine.register(FakeModule("m"))
        ctx = await engine.run_all()
        assert isinstance(ctx, ScanContext)

    async def test_sets_timestamps(self):
        engine = ScanEngine()
        engine.register(FakeModule("m"))
        ctx = await engine.run_all()
        assert ctx.started_at is not None
        assert ctx.finished_at is not None
        assert ctx.finished_at >= ctx.started_at

    async def test_collects_findings(self):
        f1 = Finding(title="A", severity=Severity.HIGH)
        f2 = Finding(title="B", severity=Severity.LOW)
        engine = ScanEngine()
        engine.register(FakeModule("mod1", findings=[f1]))
        engine.register(FakeModule("mod2", findings=[f2]))
        ctx = await engine.run_all()
        assert len(ctx.findings) == 2
        titles = {f.title for f in ctx.findings}
        assert titles == {"A", "B"}

    async def test_execution_order_preserved(self):
        OrderTracker.execution_log = []
        engine = ScanEngine()
        for name in ["first", "second", "third"]:
            engine.register(OrderTracker(name))
        await engine.run_all()
        assert OrderTracker.execution_log == ["first", "second", "third"]

    async def test_module_status_completed(self):
        engine = ScanEngine()
        mod = FakeModule("m")
        engine.register(mod)
        await engine.run_all()
        assert mod.status is ModuleStatus.COMPLETED

    async def test_clears_sensitive_after_scan(self):
        engine = ScanEngine()
        engine.ctx.auth_tokens["tok"] = "secret"
        engine.register(FakeModule("m"))
        ctx = await engine.run_all()
        assert ctx.auth_tokens == {}

    async def test_empty_engine_runs_successfully(self):
        engine = ScanEngine()
        ctx = await engine.run_all()
        assert ctx.started_at is not None
        assert ctx.finished_at is not None
        assert len(ctx.findings) == 0

    async def test_uses_provided_context(self):
        ctx = ScanContext(config={"key": "value"})
        engine = ScanEngine(ctx=ctx)
        engine.register(FakeModule("m"))
        result = await engine.run_all()
        assert result is ctx
        assert result.config["key"] == "value"


# ------------------------------------------------------------------
# Execution — run_module()
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestRunModule:

    async def test_run_single_module(self):
        f = Finding(title="Found")
        engine = ScanEngine()
        engine.register(FakeModule("target", findings=[f]))
        results = await engine.run_module("target")
        assert len(results) == 1
        assert results[0].title == "Found"

    async def test_run_module_adds_to_context(self):
        f = Finding(title="X")
        engine = ScanEngine()
        engine.register(FakeModule("m", findings=[f]))
        await engine.run_module("m")
        assert len(engine.ctx.findings) == 1

    async def test_run_nonexistent_module_raises(self):
        engine = ScanEngine()
        with pytest.raises(KeyError):
            await engine.run_module("ghost")


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestErrorHandling:

    async def test_failed_module_status(self):
        mod = FakeModule("bad", raise_on_run=RuntimeError("boom"))
        engine = ScanEngine()
        engine.register(mod)
        await engine.run_all()
        assert mod.status is ModuleStatus.FAILED

    async def test_failed_module_produces_no_findings(self):
        mod = FakeModule("bad", raise_on_run=ValueError("oops"))
        engine = ScanEngine()
        engine.register(mod)
        ctx = await engine.run_all()
        assert len(ctx.findings) == 0

    async def test_failed_module_doesnt_block_others(self):
        f = Finding(title="OK")
        bad = FakeModule("bad", raise_on_run=RuntimeError("fail"))
        good = FakeModule("good", findings=[f])
        engine = ScanEngine()
        engine.register(bad)
        engine.register(good)
        ctx = await engine.run_all()
        assert bad.status is ModuleStatus.FAILED
        assert good.status is ModuleStatus.COMPLETED
        assert len(ctx.findings) == 1

    async def test_each_module_runs_exactly_once(self):
        engine = ScanEngine()
        mods = [FakeModule(f"m{i}") for i in range(5)]
        for m in mods:
            engine.register(m)
        await engine.run_all()
        for m in mods:
            assert m.run_count == 1


# ------------------------------------------------------------------
# Introspection
# ------------------------------------------------------------------

class TestIntrospection:

    def test_modules_returns_copy(self):
        engine = ScanEngine()
        engine.register(FakeModule("m"))
        mods = engine.modules
        mods["injected"] = FakeModule("evil")
        assert "injected" not in engine.modules

    def test_status_report_empty(self):
        engine = ScanEngine()
        assert engine.status_report() == {}

    @pytest.mark.asyncio
    async def test_status_report_after_run(self):
        engine = ScanEngine()
        engine.register(FakeModule("a"))
        engine.register(FakeModule("b"))
        await engine.run_all()
        report = engine.status_report()
        assert report == {"a": "completed", "b": "completed"}

    @pytest.mark.asyncio
    async def test_status_report_mixed(self):
        engine = ScanEngine()
        engine.register(FakeModule("ok"))
        engine.register(FakeModule("fail", raise_on_run=RuntimeError("x")))
        await engine.run_all()
        report = engine.status_report()
        assert report["ok"] == "completed"
        assert report["fail"] == "failed"
