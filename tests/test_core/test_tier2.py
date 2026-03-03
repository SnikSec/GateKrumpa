"""Tests for Tier 2 platform architecture features.

Covers:
  - Target deduplication (3.4)
  - Module dependency graph + topological sort (3.1)
  - Parallel execution levels (3.2)
  - Shared HttpClient lifecycle (engine creates / injects / closes) (3.3)
  - Dependency-failure cascading / cancellation
  - ScopeManager
  - AuthProvider
  - RequestRecorder
  - Session data flow (crawler cookie capture)
"""

from __future__ import annotations

import asyncio
import base64

import pytest

from krumpa.core import (
    BaseModule,
    Finding,
    ModuleStatus,
    ScanContext,
    Severity,
    Target,
)
from krumpa.core.auth import AuthProvider
from krumpa.core.engine import ScanEngine
from krumpa.core.recorder import RequestRecord, RequestRecorder
from krumpa.core.scope import ScopeManager


# ======================================================================
# Helpers — lightweight stub modules
# ======================================================================

class _StubModule(BaseModule):
    """Minimal module that records when it runs."""

    name = "stub"
    _call_log: list[str] = []

    def __init__(self, name: str = "stub", deps: list[str] | None = None):
        super().__init__()
        self.name = name
        if deps is not None:
            self.dependencies = deps

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _StubModule._call_log.append(self.name)
        return []


class _FailModule(BaseModule):
    """Module that raises on run."""

    name = "fail"

    def __init__(self, name: str = "fail", deps: list[str] | None = None):
        super().__init__()
        self.name = name
        if deps is not None:
            self.dependencies = deps

    async def run(self, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("intentional failure")


class _FindingModule(BaseModule):
    """Module that produces a finding."""

    name = "finder"

    def __init__(self, name: str = "finder", deps: list[str] | None = None):
        super().__init__()
        self.name = name
        if deps is not None:
            self.dependencies = deps

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [Finding(title=f"found-by-{self.name}", severity=Severity.LOW)]


class _TimingModule(BaseModule):
    """Module that records wall-clock start time for parallelism testing."""

    name = "timer"
    _start_times: dict[str, float] = {}

    def __init__(self, name: str = "timer", deps: list[str] | None = None, delay: float = 0.05):
        super().__init__()
        self.name = name
        self._delay = delay
        if deps is not None:
            self.dependencies = deps

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _TimingModule._start_times[self.name] = asyncio.get_event_loop().time()
        await asyncio.sleep(self._delay)
        return []


# ======================================================================
# Target deduplication
# ======================================================================

class TestTargetDeduplication:

    def test_duplicate_url_method_not_added_twice(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/api", method="GET"))
        ctx.add_target(Target(url="https://a.com/api", method="GET"))
        assert len(ctx.targets) == 1

    def test_different_methods_are_separate(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/api", method="GET"))
        ctx.add_target(Target(url="https://a.com/api", method="POST"))
        assert len(ctx.targets) == 2

    def test_metadata_merged_on_duplicate(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/", metadata={"a": 1}))
        ctx.add_target(Target(url="https://a.com/", metadata={"b": 2}))
        assert len(ctx.targets) == 1
        assert ctx.targets[0].metadata == {"a": 1, "b": 2}

    def test_headers_merged_on_duplicate(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/", headers={"X-A": "1"}))
        ctx.add_target(Target(url="https://a.com/", headers={"X-B": "2"}))
        assert ctx.targets[0].headers == {"X-A": "1", "X-B": "2"}

    def test_body_filled_on_duplicate_when_missing(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/", method="POST"))
        ctx.add_target(Target(url="https://a.com/", method="POST", body='{"x":1}'))
        assert ctx.targets[0].body == '{"x":1}'

    def test_body_not_overwritten_when_present(self):
        ctx = ScanContext()
        ctx.add_target(Target(url="https://a.com/", method="POST", body="original"))
        ctx.add_target(Target(url="https://a.com/", method="POST", body="new"))
        assert ctx.targets[0].body == "original"

    def test_many_duplicates_single_entry(self):
        ctx = ScanContext()
        for i in range(50):
            ctx.add_target(Target(url="https://a.com/", metadata={"i": i}))
        assert len(ctx.targets) == 1
        assert ctx.targets[0].metadata["i"] == 49


# ======================================================================
# Topological sort (dependency graph)
# ======================================================================

class TestTopologicalSort:

    def test_no_deps_preserves_order(self):
        engine = ScanEngine()
        engine.register(_StubModule("A"))
        engine.register(_StubModule("B"))
        engine.register(_StubModule("C"))
        order = engine._topological_sort()
        assert order == ["A", "B", "C"]

    def test_simple_chain(self):
        engine = ScanEngine()
        engine.register(_StubModule("C", deps=["B"]))
        engine.register(_StubModule("B", deps=["A"]))
        engine.register(_StubModule("A"))
        order = engine._topological_sort()
        assert order.index("A") < order.index("B") < order.index("C")

    def test_diamond_dependency(self):
        engine = ScanEngine()
        engine.register(_StubModule("D", deps=["B", "C"]))
        engine.register(_StubModule("B", deps=["A"]))
        engine.register(_StubModule("C", deps=["A"]))
        engine.register(_StubModule("A"))
        order = engine._topological_sort()
        assert order.index("A") < order.index("B")
        assert order.index("A") < order.index("C")
        assert order.index("B") < order.index("D")
        assert order.index("C") < order.index("D")

    def test_cycle_raises(self):
        engine = ScanEngine()
        engine.register(_StubModule("A", deps=["B"]))
        engine.register(_StubModule("B", deps=["A"]))
        with pytest.raises(ValueError, match="cycle"):
            engine._topological_sort()

    def test_unregistered_dep_ignored(self):
        engine = ScanEngine()
        engine.register(_StubModule("A", deps=["MISSING"]))
        order = engine._topological_sort()
        assert order == ["A"]


# ======================================================================
# Execution levels (parallelism grouping)
# ======================================================================

class TestExecutionLevels:

    def test_all_independent_single_level(self):
        engine = ScanEngine()
        engine.register(_StubModule("A"))
        engine.register(_StubModule("B"))
        engine.register(_StubModule("C"))
        levels = engine._build_execution_levels()
        assert len(levels) == 1
        assert set(levels[0]) == {"A", "B", "C"}

    def test_chain_produces_n_levels(self):
        engine = ScanEngine()
        engine.register(_StubModule("A"))
        engine.register(_StubModule("B", deps=["A"]))
        engine.register(_StubModule("C", deps=["B"]))
        levels = engine._build_execution_levels()
        assert len(levels) == 3
        assert levels[0] == ["A"]
        assert levels[1] == ["B"]
        assert levels[2] == ["C"]

    def test_diamond_two_levels_in_middle(self):
        engine = ScanEngine()
        engine.register(_StubModule("root"))
        engine.register(_StubModule("left", deps=["root"]))
        engine.register(_StubModule("right", deps=["root"]))
        engine.register(_StubModule("join", deps=["left", "right"]))
        levels = engine._build_execution_levels()
        assert levels[0] == ["root"]
        assert set(levels[1]) == {"left", "right"}
        assert levels[2] == ["join"]

    def test_gatekrumpa_module_graph(self):
        """Verify the actual GateKrumpa module dependency levels."""
        engine = ScanEngine()
        engine.register(_StubModule("SneakyGits", deps=[]))
        engine.register(_StubModule("OpenKrump", deps=[]))
        engine.register(_StubModule("BossKey", deps=["SneakyGits"]))
        engine.register(_StubModule("WaaaghLogic", deps=["SneakyGits"]))
        engine.register(_StubModule("GrotAssault", deps=["SneakyGits"]))
        engine.register(_StubModule("RedTeef", deps=["GrotAssault"]))
        engine.register(_StubModule("WaaaghGate", deps=["RedTeef", "BossKey", "WaaaghLogic", "OpenKrump"]))
        levels = engine._build_execution_levels()
        assert set(levels[0]) == {"SneakyGits", "OpenKrump"}
        assert set(levels[1]) == {"BossKey", "WaaaghLogic", "GrotAssault"}
        assert levels[2] == ["RedTeef"]
        assert levels[3] == ["WaaaghGate"]


# ======================================================================
# Engine — run_all with shared HttpClient
# ======================================================================

class TestEngineRunAll:

    @pytest.mark.asyncio
    async def test_http_client_injected_and_closed(self):
        """Engine creates HttpClient, sets on ctx, and closes after."""
        engine = ScanEngine()
        engine.register(_StubModule("A"))
        ctx = await engine.run_all()
        # After run_all, http_client should be None (closed)
        assert ctx.http_client is None

    @pytest.mark.asyncio
    async def test_http_client_available_during_run(self):
        """Module can access ctx.http_client while running."""

        class _ClientChecker(BaseModule):
            name = "checker"
            saw_client = False

            async def run(self, ctx):
                _ClientChecker.saw_client = ctx.http_client is not None
                return []

        engine = ScanEngine()
        engine.register(_ClientChecker())
        await engine.run_all()
        assert _ClientChecker.saw_client

    @pytest.mark.asyncio
    async def test_modules_execute_in_dependency_order(self):
        _StubModule._call_log = []
        engine = ScanEngine()
        engine.register(_StubModule("B", deps=["A"]))
        engine.register(_StubModule("A"))
        await engine.run_all()
        assert _StubModule._call_log.index("A") < _StubModule._call_log.index("B")

    @pytest.mark.asyncio
    async def test_findings_collected_across_modules(self):
        engine = ScanEngine()
        engine.register(_FindingModule("mod1"))
        engine.register(_FindingModule("mod2"))
        ctx = await engine.run_all()
        assert len(ctx.findings) == 2

    @pytest.mark.asyncio
    async def test_failed_module_cancels_dependants(self):
        engine = ScanEngine()
        engine.register(_FailModule("A"))
        engine.register(_StubModule("B", deps=["A"]))
        ctx = await engine.run_all()
        assert engine.modules["A"].status == ModuleStatus.FAILED
        assert engine.modules["B"].status == ModuleStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cascading_cancellation(self):
        engine = ScanEngine()
        engine.register(_FailModule("A"))
        engine.register(_StubModule("B", deps=["A"]))
        engine.register(_StubModule("C", deps=["B"]))
        ctx = await engine.run_all()
        assert engine.modules["A"].status == ModuleStatus.FAILED
        assert engine.modules["B"].status == ModuleStatus.CANCELLED
        assert engine.modules["C"].status == ModuleStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_http_config_forwarded(self):
        """http_config kwargs are passed to HttpClient constructor."""
        engine = ScanEngine(http_config={"timeout": 5.0, "retries": 0})

        class _ConfigChecker(BaseModule):
            name = "cfgcheck"
            timeout_seen = None

            async def run(self, ctx):
                _ConfigChecker.timeout_seen = ctx.http_client._client.timeout.read
                return []

        engine.register(_ConfigChecker())
        await engine.run_all()
        assert _ConfigChecker.timeout_seen == 5.0


# ======================================================================
# Parallel execution timing
# ======================================================================

class TestParallelExecution:

    @pytest.mark.asyncio
    async def test_independent_modules_run_concurrently(self):
        """Two modules with no deps should start at ~same time."""
        _TimingModule._start_times = {}
        engine = ScanEngine()
        engine.register(_TimingModule("P1", delay=0.1))
        engine.register(_TimingModule("P2", delay=0.1))
        await engine.run_all()
        t1 = _TimingModule._start_times["P1"]
        t2 = _TimingModule._start_times["P2"]
        # If sequential, gap would be ~0.1s. If parallel, ~0s.
        assert abs(t1 - t2) < 0.05

    @pytest.mark.asyncio
    async def test_dependent_module_waits(self):
        """Module with dep should start after dep finishes."""
        _TimingModule._start_times = {}
        engine = ScanEngine()
        engine.register(_TimingModule("fast", delay=0.1))
        engine.register(_TimingModule("after", deps=["fast"], delay=0.01))
        await engine.run_all()
        t_fast = _TimingModule._start_times["fast"]
        t_after = _TimingModule._start_times["after"]
        assert t_after > t_fast + 0.05  # started after fast finished


# ======================================================================
# ScopeManager
# ======================================================================

class TestScopeManager:

    def test_no_rules_everything_in_scope(self):
        scope = ScopeManager()
        assert scope.is_in_scope("https://anything.com/path") is True

    def test_include_whitelists(self):
        scope = ScopeManager(include_patterns=[r"https://api\.example\.com"])
        assert scope.is_in_scope("https://api.example.com/v1") is True
        assert scope.is_in_scope("https://evil.com/") is False

    def test_exclude_blacklists(self):
        scope = ScopeManager(exclude_patterns=[r"\.internal\."])
        assert scope.is_in_scope("https://api.internal.corp/v1") is False
        assert scope.is_in_scope("https://api.public.com/v1") is True

    def test_exclude_takes_priority(self):
        scope = ScopeManager(
            include_patterns=[r"example\.com"],
            exclude_patterns=[r"/admin"],
        )
        assert scope.is_in_scope("https://example.com/api") is True
        assert scope.is_in_scope("https://example.com/admin") is False

    def test_case_insensitive(self):
        scope = ScopeManager(include_patterns=[r"example\.com"])
        assert scope.is_in_scope("https://EXAMPLE.COM/api") is True

    def test_multiple_includes(self):
        scope = ScopeManager(include_patterns=[r"api\.a\.com", r"api\.b\.com"])
        assert scope.is_in_scope("https://api.a.com/v1") is True
        assert scope.is_in_scope("https://api.b.com/v1") is True
        assert scope.is_in_scope("https://api.c.com/v1") is False

    def test_repr(self):
        scope = ScopeManager(include_patterns=["a"], exclude_patterns=["b", "c"])
        assert "includes=1" in repr(scope)
        assert "excludes=2" in repr(scope)


# ======================================================================
# AuthProvider
# ======================================================================

class TestAuthProvider:

    def test_bearer_injection(self):
        auth = AuthProvider("bearer", token="tok123")
        headers = auth.inject({"Content-Type": "application/json"})
        assert headers["Authorization"] == "Bearer tok123"
        assert headers["Content-Type"] == "application/json"

    def test_api_key_injection(self):
        auth = AuthProvider("api_key", api_key="mykey")
        headers = auth.inject()
        assert headers["X-API-Key"] == "mykey"

    def test_api_key_custom_header(self):
        auth = AuthProvider("api_key", api_key="mykey", api_key_header="X-Custom")
        headers = auth.inject()
        assert headers["X-Custom"] == "mykey"

    def test_basic_auth(self):
        auth = AuthProvider("basic", username="admin", password="secret")
        headers = auth.inject()
        expected = base64.b64encode(b"admin:secret").decode()
        assert headers["Authorization"] == f"Basic {expected}"

    def test_custom_headers(self):
        auth = AuthProvider("custom", custom_headers={"X-Org": "corp", "X-Team": "sec"})
        headers = auth.inject()
        assert headers["X-Org"] == "corp"
        assert headers["X-Team"] == "sec"

    def test_no_overwrite_existing(self):
        auth = AuthProvider("bearer", token="new")
        headers = auth.inject({"Authorization": "Bearer old"})
        assert headers["Authorization"] == "Bearer old"

    def test_none_auth_type(self):
        auth = AuthProvider("none")
        headers = auth.inject({"X-A": "1"})
        assert headers == {"X-A": "1"}

    def test_repr(self):
        assert "bearer" in repr(AuthProvider("bearer"))


# ======================================================================
# RequestRecorder
# ======================================================================

class TestRequestRecorder:

    def test_record_and_retrieve(self):
        rec = RequestRecorder()
        entry = RequestRecord(method="GET", url="https://a.com", status_code=200)
        rec.record(entry)
        assert rec.count == 1
        assert rec.records[0].url == "https://a.com"

    def test_max_records_limit(self):
        rec = RequestRecorder(max_records=3)
        for i in range(5):
            rec.record(RequestRecord(method="GET", url=f"https://a.com/{i}", status_code=200))
        assert rec.count == 3
        # Oldest should be dropped
        assert rec.records[0].url == "https://a.com/2"

    def test_clear(self):
        rec = RequestRecorder()
        rec.record(RequestRecord(method="GET", url="https://a.com", status_code=200))
        rec.clear()
        assert rec.count == 0

    def test_records_returns_copy(self):
        rec = RequestRecorder()
        rec.record(RequestRecord(method="GET", url="https://a.com", status_code=200))
        copy = rec.records
        copy.clear()
        assert rec.count == 1

    def test_to_dict(self):
        entry = RequestRecord(method="POST", url="https://a.com/api", status_code=201)
        d = entry.to_dict()
        assert d["method"] == "POST"
        assert d["status_code"] == 201
        assert "timestamp" in d


# ======================================================================
# BaseModule.dependencies attribute
# ======================================================================

class TestBaseModuleDependencies:

    def test_default_empty(self):
        mod = _StubModule("x")
        assert mod.dependencies == []

    def test_custom_deps(self):
        mod = _StubModule("x", deps=["A", "B"])
        assert mod.dependencies == ["A", "B"]


# ======================================================================
# Session data flow — crawler cookie capture
# ======================================================================

class TestCrawlerCookieCapture:

    def test_captured_cookies_initially_empty(self):
        from krumpa.sneakygits.crawler import Crawler
        c = Crawler()
        assert c.captured_cookies == {}

    def test_captured_cookies_populated(self):
        """Verify the property returns cookies set on the internal dict."""
        from krumpa.sneakygits.crawler import Crawler
        c = Crawler()
        c._captured_cookies["https://a.com"] = ["session=abc; Path=/"]
        cookies = c.captured_cookies
        assert "https://a.com" in cookies
        assert cookies["https://a.com"] == ["session=abc; Path=/"]


# ======================================================================
# ScanContext.http_client field
# ======================================================================

class TestScanContextHttpClient:

    def test_default_none(self):
        ctx = ScanContext()
        assert ctx.http_client is None

    def test_can_be_set(self):
        ctx = ScanContext()
        ctx.http_client = "fake_client"
        assert ctx.http_client == "fake_client"
