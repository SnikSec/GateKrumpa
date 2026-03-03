"""Tests for FlowAnalyzer — workflow step skipping, parameter tampering, replay."""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest

from krumpa.core import Severity, Target
from krumpa.waaaghlogic.flow_analyzer import FlowAnalyzer, WorkflowStep


# ------------------------------------------------------------------
# Fake HTTP
# ------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeHttpClient:
    """Configurable fake: maps (method, url) → response, with optional body inspection."""

    def __init__(
        self,
        responses: dict[tuple[str, str], _FakeResponse] | None = None,
        *,
        default_status: int = 200,
        body_validator: Any = None,
    ):
        self._responses = responses or {}
        self._default_status = default_status
        # Optional callback: (method, url, body) → _FakeResponse | None
        self._body_validator = body_validator
        self.request_log: list[dict] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.request_log.append({"method": method, "url": url, "body": json_body})

        if self._body_validator:
            override = self._body_validator(method, url, json_body)
            if override is not None:
                return override

        key = (method.upper(), url)
        if key in self._responses:
            return self._responses[key]
        return _FakeResponse(status_code=self._default_status)

    async def close(self):
        pass


def _target() -> Target:
    return Target(url="https://example.com")


# ------------------------------------------------------------------
# Step skipping
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestStepSkipping:

    async def test_detects_skippable_step(self):
        """If step 2 returns 200 without step 1 → finding."""
        steps = [
            WorkflowStep(name="Select Item", url="https://example.com/cart/add"),
            WorkflowStep(name="Checkout", url="https://example.com/checkout"),
            WorkflowStep(name="Pay", url="https://example.com/pay"),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        skip_findings = [f for f in findings if "step skipping" in f.title.lower()]
        # Steps 2 and 3 should be flagged (accessible without prior steps)
        assert len(skip_findings) == 2

    async def test_no_finding_when_blocked(self):
        """If later steps return 403 → no step-skipping finding."""
        steps = [
            WorkflowStep(name="Start", url="https://example.com/start"),
            WorkflowStep(name="Finish", url="https://example.com/finish"),
        ]
        client = _FakeHttpClient(responses={
            ("POST", "https://example.com/start"): _FakeResponse(200),
            ("POST", "https://example.com/finish"): _FakeResponse(403, "forbidden"),
        })
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        skip_findings = [f for f in findings if "step skipping" in f.title.lower()]
        assert skip_findings == []

    async def test_first_step_not_flagged(self):
        """Step 1 is never flagged for skipping."""
        steps = [
            WorkflowStep(name="Only Step", url="https://example.com/do"),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        skip_findings = [f for f in findings if "step skipping" in f.title.lower()]
        assert skip_findings == []


# ------------------------------------------------------------------
# Parameter tampering
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestParameterTampering:

    async def test_detects_tampered_price(self):
        """If price=0 is accepted → finding."""
        steps = [
            WorkflowStep(
                name="Purchase",
                url="https://example.com/buy",
                body={"item": "widget", "price": 9.99, "quantity": 1},
                tamper_fields=["price"],
            ),
        ]

        def validator(method, url, body):
            if body and body.get("price", 9.99) <= 0:
                return _FakeResponse(200, '{"status": "ok"}')
            return _FakeResponse(200, '{"status": "ok"}')

        client = _FakeHttpClient(body_validator=validator)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        tamper_findings = [f for f in findings if "parameter tampering" in f.title.lower()]
        assert len(tamper_findings) >= 1

    async def test_no_finding_when_rejected(self):
        """If tampered values are rejected → no finding."""
        steps = [
            WorkflowStep(
                name="Purchase",
                url="https://example.com/buy",
                body={"item": "widget", "price": 9.99},
                tamper_fields=["price"],
            ),
        ]

        def validator(method, url, body):
            if body and body.get("price") != 9.99:
                return _FakeResponse(400, '{"error": "invalid price"}')
            return _FakeResponse(200, '{"status": "ok"}')

        client = _FakeHttpClient(body_validator=validator)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        tamper_findings = [f for f in findings if "parameter tampering" in f.title.lower()]
        assert tamper_findings == []

    async def test_no_tamper_when_no_fields_specified(self):
        steps = [
            WorkflowStep(
                name="Purchase",
                url="https://example.com/buy",
                body={"price": 9.99},
                tamper_fields=[],  # nothing to tamper
            ),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        tamper_findings = [f for f in findings if "parameter tampering" in f.title.lower()]
        assert tamper_findings == []

    async def test_role_tampering(self):
        steps = [
            WorkflowStep(
                name="Update Profile",
                url="https://example.com/profile",
                body={"name": "user1", "role": "viewer"},
                tamper_fields=["role"],
            ),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        tamper_findings = [f for f in findings if "parameter tampering" in f.title.lower()]
        assert len(tamper_findings) >= 1


# ------------------------------------------------------------------
# Replay
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestReplay:

    async def test_detects_replay(self):
        """If same POST succeeds twice → finding."""
        steps = [
            WorkflowStep(name="Transfer", url="https://example.com/transfer", method="POST"),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        replay_findings = [f for f in findings if "replay" in f.title.lower()]
        assert len(replay_findings) == 1

    async def test_no_replay_for_get(self):
        """GET requests are not tested for replay."""
        steps = [
            WorkflowStep(name="View", url="https://example.com/view", method="GET"),
        ]
        client = _FakeHttpClient(default_status=200)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        replay_findings = [f for f in findings if "replay" in f.title.lower()]
        assert replay_findings == []

    async def test_no_replay_when_second_fails(self):
        call_count = 0

        def validator(method, url, body):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return _FakeResponse(200)
            return _FakeResponse(409, "conflict")

        steps = [
            WorkflowStep(name="Submit", url="https://example.com/submit", method="POST"),
        ]
        client = _FakeHttpClient(body_validator=validator)
        analyzer = FlowAnalyzer(http_client=client)
        findings = await analyzer.test_workflow(steps, _target())
        replay_findings = [f for f in findings if "replay" in f.title.lower()]
        assert replay_findings == []


# ------------------------------------------------------------------
# Mutation helpers
# ------------------------------------------------------------------

class TestGetMutations:

    def test_price_mutations(self):
        fa = FlowAnalyzer()
        muts = fa._get_mutations("total_price")
        assert 0 in muts
        assert -1 in muts

    def test_role_mutations(self):
        fa = FlowAnalyzer()
        muts = fa._get_mutations("user_role")
        assert "admin" in muts

    def test_unknown_field_fallback(self):
        fa = FlowAnalyzer()
        muts = fa._get_mutations("some_random_field")
        assert len(muts) > 0  # Should return fallback values
