"""Tests for BaseModule — lifecycle, abstract enforcement, helpers."""

from __future__ import annotations

from typing import List

import pytest

from krumpa.core import BaseModule, Finding, ModuleStatus, ScanContext, Severity


# ------------------------------------------------------------------
# Concrete test module
# ------------------------------------------------------------------

class DummyModule(BaseModule):
    """Minimal concrete implementation for testing."""

    name = "dummy"
    description = "A dummy module for testing"

    def __init__(self, *, findings_to_return: List[Finding] | None = None,
                 raise_on_run: Exception | None = None):
        super().__init__()
        self._findings_to_return = findings_to_return or []
        self._raise_on_run = raise_on_run
        self.setup_called = False
        self.teardown_called = False

    async def run(self, ctx: ScanContext) -> List[Finding]:
        if self._raise_on_run:
            raise self._raise_on_run
        return list(self._findings_to_return)

    async def setup(self, ctx: ScanContext) -> None:
        self.setup_called = True

    async def teardown(self, ctx: ScanContext) -> None:
        self.teardown_called = True


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestBaseModuleInit:

    def test_initial_status_is_idle(self):
        mod = DummyModule()
        assert mod.status is ModuleStatus.IDLE

    def test_initial_findings_empty(self):
        mod = DummyModule()
        assert mod.findings == []

    def test_name_and_description(self):
        mod = DummyModule()
        assert mod.name == "dummy"
        assert mod.description == "A dummy module for testing"


class TestAbstractEnforcement:

    def test_cannot_instantiate_basemodule_directly(self):
        with pytest.raises(TypeError):
            BaseModule()

    def test_must_implement_run(self):
        class Incomplete(BaseModule):
            name = "inc"

        with pytest.raises(TypeError):
            Incomplete()


class TestAddFinding:

    def test_sets_module_name_on_finding(self):
        mod = DummyModule()
        f = Finding(title="Test")
        mod.add_finding(f)
        assert f.module == "dummy"

    def test_appends_to_findings_list(self):
        mod = DummyModule()
        mod.add_finding(Finding(title="A"))
        mod.add_finding(Finding(title="B"))
        assert len(mod.findings) == 2
        assert mod.findings[0].title == "A"
        assert mod.findings[1].title == "B"


class TestReset:

    def test_clears_findings(self):
        mod = DummyModule()
        mod.add_finding(Finding(title="X"))
        mod.reset()
        assert mod.findings == []

    def test_resets_status_to_idle(self):
        mod = DummyModule()
        mod.status = ModuleStatus.COMPLETED
        mod.reset()
        assert mod.status is ModuleStatus.IDLE


@pytest.mark.asyncio
class TestLifecycle:

    async def test_run_returns_findings(self):
        f = Finding(title="Found it")
        mod = DummyModule(findings_to_return=[f])
        ctx = ScanContext()
        results = await mod.run(ctx)
        assert len(results) == 1
        assert results[0].title == "Found it"

    async def test_setup_called(self):
        mod = DummyModule()
        ctx = ScanContext()
        await mod.setup(ctx)
        assert mod.setup_called is True

    async def test_teardown_called(self):
        mod = DummyModule()
        ctx = ScanContext()
        await mod.teardown(ctx)
        assert mod.teardown_called is True

    async def test_default_setup_is_noop(self):
        """A module without overriding setup should not error."""
        class NoSetup(BaseModule):
            name = "no-setup"
            async def run(self, ctx):
                return []

        mod = NoSetup()
        await mod.setup(ScanContext())  # should not raise

    async def test_default_teardown_is_noop(self):
        class NoTeardown(BaseModule):
            name = "no-td"
            async def run(self, ctx):
                return []

        mod = NoTeardown()
        await mod.teardown(ScanContext())  # should not raise


class TestRepr:

    def test_repr_contains_name_and_status(self):
        mod = DummyModule()
        r = repr(mod)
        assert "dummy" in r
        assert "idle" in r

    def test_repr_after_status_change(self):
        mod = DummyModule()
        mod.status = ModuleStatus.RUNNING
        assert "running" in repr(mod)
