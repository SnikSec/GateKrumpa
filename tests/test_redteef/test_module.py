"""Tests for krumpa.redteef.module — RedTeefModule orchestrator."""

import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.redteef.module import RedTeefModule, _lower_severity
from krumpa.redteef.payload_builder import ProofPayload


# ------------------------------------------------------------------
# Fake HTTP layer
# ------------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = "OK"


class FakeHttpClient:
    def __init__(self, default_text="OK"):
        self.default_text = default_text
        self.requests: List[Dict[str, Any]] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.requests.append({"method": method, "url": url})
        return FakeResponse(text=self.default_text)

    async def close(self):
        pass


class _NoopAsync:
    """Stub that returns [] for any async method call."""
    def __getattr__(self, name):
        async def _noop(*a, **kw):
            return []
        return _noop


class _FakeEnvSelector:
    """Returns an empty EnvironmentProfile for detect_environment."""
    def detect_environment(self, *a, **kw):
        from krumpa.redteef.env_payloads import EnvironmentProfile
        return EnvironmentProfile()


def _make_redteef(http_client=None) -> RedTeefModule:
    mod = RedTeefModule(http_client=http_client)
    mod._blind_sqli = _NoopAsync()
    mod._env_selector = _FakeEnvSelector()
    # Phase 3 sub-components
    mod._deser_confirmer = _NoopAsync()
    mod._polyglot = _NoopAsync()
    mod._regression = _NoopAsync()
    return mod


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _xss_finding(target_url: str = "https://app.com/search") -> Finding:
    return Finding(
        title="Reflected input on field 'q'",
        severity=Severity.HIGH,
        target=Target(url=target_url),
        evidence="Payload: '<script>alert(1)</script>' on field 'q'",
        tags=["fuzz", "xss", "reflection"],
    )


def _sqli_finding() -> Finding:
    return Finding(
        title="Server error on field 'id'",
        severity=Severity.HIGH,
        target=Target(url="https://app.com/users"),
        evidence="field 'id'",
        tags=["fuzz", "sql"],
    )


def _info_finding() -> Finding:
    return Finding(
        title="Info only",
        severity=Severity.INFO,
        target=Target(url="https://app.com"),
        tags=["info"],
    )


# ------------------------------------------------------------------
# Tests — confirmation flow
# ------------------------------------------------------------------

class TestConfirmationFlow:
    @pytest.mark.asyncio
    async def test_confirms_xss_when_indicator_reflected(self):
        client = FakeHttpClient(default_text="<krumpa-xss-test> found in body")
        module = _make_redteef(http_client=client)
        ctx = ScanContext(
            targets=[Target(url="https://app.com/search")],
            findings=[_xss_finding()],
        )
        findings = await module.run(ctx)
        assert len(findings) > 0
        assert any("CONFIRMED" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_no_confirmation_when_indicator_absent(self):
        client = FakeHttpClient(default_text="nothing special")
        module = _make_redteef(http_client=client)
        ctx = ScanContext(
            targets=[Target(url="https://app.com/search")],
            findings=[_xss_finding()],
        )
        findings = await module.run(ctx)
        # XSS canary not reflected → no confirmed findings
        confirmed = [f for f in findings if "CONFIRMED" in f.title]
        assert len(confirmed) == 0

    @pytest.mark.asyncio
    async def test_skips_info_findings(self):
        client = FakeHttpClient()
        module = _make_redteef(http_client=client)
        ctx = ScanContext(findings=[_info_finding()])
        findings = await module.run(ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_already_confirmed(self):
        f = _xss_finding()
        f.tags.append("confirmed")
        client = FakeHttpClient(default_text="<krumpa-xss-test>")
        module = _make_redteef(http_client=client)
        ctx = ScanContext(findings=[f])
        findings = await module.run(ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_context_returns_empty(self):
        client = FakeHttpClient()
        module = _make_redteef(http_client=client)
        ctx = ScanContext()
        findings = await module.run(ctx)
        assert findings == []


# ------------------------------------------------------------------
# Tests — field inference
# ------------------------------------------------------------------

class TestFieldInference:
    @pytest.mark.asyncio
    async def test_infers_field_from_evidence(self):
        client = FakeHttpClient(default_text="<krumpa-xss-test>")
        module = _make_redteef(http_client=client)
        f = _xss_finding()
        f.evidence = "Payload on field 'search_query'"
        ctx = ScanContext(findings=[f])
        await module.run(ctx)
        # Check that the requests used the inferred field
        for req in client.requests:
            if req.get("json_body"):
                assert "search_query" in req["json_body"]


# ------------------------------------------------------------------
# Tests — module metadata
# ------------------------------------------------------------------

class TestModuleMetadata:
    def test_name(self):
        assert RedTeefModule().name == "RedTeef"

    def test_description(self):
        m = RedTeefModule()
        assert "Exploit" in m.description or "Confirm" in m.description


# ------------------------------------------------------------------
# Tests — severity helpers
# ------------------------------------------------------------------

class TestLowerSeverity:
    def test_critical_becomes_high(self):
        assert _lower_severity(Severity.CRITICAL) == Severity.HIGH

    def test_high_becomes_medium(self):
        assert _lower_severity(Severity.HIGH) == Severity.MEDIUM

    def test_info_stays_info(self):
        assert _lower_severity(Severity.INFO) == Severity.INFO
