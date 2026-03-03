"""Tests for krumpa.waaaghgate.module — WaaaghGateModule orchestrator."""

import pytest
from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.waaaghgate.module import WaaaghGateModule
from krumpa.waaaghgate.gate import GatePolicy
from krumpa.waaaghgate.reporter import ReportFormat


def _finding(sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title="Test", severity=sev,
        target=Target(url="https://example.com"),
    )


class TestWaaaghGateModule:
    @pytest.mark.asyncio
    async def test_returns_no_new_findings(self):
        module = WaaaghGateModule()
        ctx = ScanContext(findings=[_finding()])
        result = await module.run(ctx)
        assert result == []

    @pytest.mark.asyncio
    async def test_gate_result_stored(self):
        module = WaaaghGateModule()
        ctx = ScanContext(findings=[_finding(Severity.CRITICAL)])
        await module.run(ctx)
        assert module.gate_result is not None
        assert not module.gate_result.passed

    @pytest.mark.asyncio
    async def test_gate_passes_clean_scan(self):
        module = WaaaghGateModule()
        ctx = ScanContext(findings=[_finding(Severity.LOW)])
        await module.run(ctx)
        assert module.gate_result.passed

    @pytest.mark.asyncio
    async def test_reports_generated(self):
        module = WaaaghGateModule(
            report_formats=[ReportFormat.JSON, ReportFormat.MARKDOWN],
        )
        ctx = ScanContext(findings=[_finding()])
        await module.run(ctx)
        assert ReportFormat.JSON in module.reports
        assert ReportFormat.MARKDOWN in module.reports

    @pytest.mark.asyncio
    async def test_context_metadata_updated(self):
        module = WaaaghGateModule()
        ctx = ScanContext(findings=[])
        await module.run(ctx)
        assert ctx.metadata["gate_passed"] is True
        assert ctx.metadata["gate_exit_code"] == 0

    @pytest.mark.asyncio
    async def test_context_metadata_on_failure(self):
        module = WaaaghGateModule()
        ctx = ScanContext(findings=[_finding(Severity.CRITICAL)])
        await module.run(ctx)
        assert ctx.metadata["gate_passed"] is False
        assert ctx.metadata["gate_exit_code"] == 1

    @pytest.mark.asyncio
    async def test_custom_policy(self):
        policy = GatePolicy(fail_on={Severity.LOW: 0})
        module = WaaaghGateModule(policy=policy)
        ctx = ScanContext(findings=[_finding(Severity.LOW)])
        await module.run(ctx)
        assert not module.gate_result.passed

    @pytest.mark.asyncio
    async def test_module_metadata(self):
        m = WaaaghGateModule()
        assert m.name == "WaaaghGate"
        assert "CI" in m.description or "Gate" in m.description
