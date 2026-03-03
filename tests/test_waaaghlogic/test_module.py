"""Tests for WaaaghLogicModule orchestrator."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.waaaghlogic.flow_analyzer import WorkflowStep
from krumpa.waaaghlogic.module import WaaaghLogicModule


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class _FakeFlowAnalyzer:
    def __init__(self, findings=None):
        self._findings = findings or []
        self.tested_workflows: list = []

    async def test_workflow(self, steps, target):
        self.tested_workflows.append(steps)
        return list(self._findings)


class _FakeIdempotencyChecker:
    def __init__(self, findings=None):
        self._findings = findings or []
        self.checked_urls: list[str] = []

    async def check(self, url, target, *, method="POST", body=None, expected_status=200):
        self.checked_urls.append(url)
        return list(self._findings)


def _make_module(
    flow_findings=None,
    idem_findings=None,
    workflows=None,
    idempotency_targets=None,
) -> WaaaghLogicModule:
    mod = WaaaghLogicModule(
        workflows=workflows,
        idempotency_targets=idempotency_targets,
    )
    mod._flow_analyzer = _FakeFlowAnalyzer(flow_findings)
    mod._idempotency_checker = _FakeIdempotencyChecker(idem_findings)
    return mod


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestWaaaghLogicModule:

    async def test_empty_context_no_findings(self):
        mod = _make_module()
        findings = await mod.run(ScanContext())
        assert findings == []

    async def test_workflow_findings_returned(self):
        f = Finding(title="Step skip", severity=Severity.HIGH)
        workflow = [
            WorkflowStep(name="A", url="https://example.com/a"),
            WorkflowStep(name="B", url="https://example.com/b"),
        ]
        mod = _make_module(flow_findings=[f], workflows=[workflow])
        findings = await mod.run(ScanContext())
        assert len(findings) == 1
        assert findings[0].title == "Step skip"

    async def test_idempotency_targets_checked(self):
        f = Finding(title="Duplicate", severity=Severity.MEDIUM)
        mod = _make_module(
            idem_findings=[f],
            idempotency_targets=[{"url": "https://example.com/pay", "method": "POST"}],
        )
        findings = await mod.run(ScanContext())
        assert any("Duplicate" in fi.title for fi in findings)
        assert "https://example.com/pay" in mod._idempotency_checker.checked_urls

    async def test_auto_detects_state_changing_targets(self):
        mod = _make_module()
        ctx = ScanContext(targets=[
            Target(url="https://example.com/api/transfer", method="POST"),
            Target(url="https://example.com/about", method="GET"),
        ])
        auto = mod._detect_state_changing(ctx)
        urls = [u for u, m in auto]
        assert "https://example.com/api/transfer" in urls
        assert "https://example.com/about" not in urls

    async def test_auto_detect_deduplicates(self):
        mod = _make_module()
        ctx = ScanContext(targets=[
            Target(url="https://example.com/submit", method="POST"),
            Target(url="https://example.com/submit", method="POST"),
        ])
        auto = mod._detect_state_changing(ctx)
        assert len(auto) == 1

    async def test_findings_registered_on_module(self):
        f = Finding(title="test finding", severity=Severity.LOW)
        workflow = [WorkflowStep(name="X", url="https://example.com/x")]
        mod = _make_module(flow_findings=[f], workflows=[workflow])
        await mod.run(ScanContext())
        assert len(mod.findings) == 1
        assert mod.findings[0].module == "WaaaghLogic"

    async def test_module_attributes(self):
        mod = WaaaghLogicModule()
        assert mod.name == "WaaaghLogic"
        assert "Business Logic" in mod.description

    async def test_multiple_workflows(self):
        f = Finding(title="found", severity=Severity.MEDIUM)
        wf1 = [WorkflowStep(name="A", url="https://a.com/1")]
        wf2 = [WorkflowStep(name="B", url="https://b.com/1")]
        mod = _make_module(flow_findings=[f], workflows=[wf1, wf2])
        findings = await mod.run(ScanContext())
        assert len(findings) == 2  # one per workflow
        assert len(mod._flow_analyzer.tested_workflows) == 2

    async def test_empty_workflow_skipped(self):
        mod = _make_module(workflows=[[]])
        findings = await mod.run(ScanContext())
        assert findings == []
        assert mod._flow_analyzer.tested_workflows == []
