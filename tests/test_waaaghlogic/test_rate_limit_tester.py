"""Tests for RateLimitTester — business-layer rate-limit detection."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.waaaghlogic.rate_limit_tester import (
    RateLimitTester,
    RateLimitTarget,
    BurstResult,
    _DEFAULT_BURST,
    _DEFAULT_CONCURRENCY,
    _DEFAULT_SUCCESS_THRESHOLD,
)


# ------------------------------------------------------------------
# Fake HTTP clients
# ------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class _AlwaysSucceedClient:
    """Every request returns 200 — no rate limiting."""

    def __init__(self):
        self.call_count = 0

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.call_count += 1
        return _FakeResponse(200)

    async def close(self):
        pass


class _AlwaysRateLimitClient:
    """Every request returns 429 — strong rate limiting."""

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        return _FakeResponse(429)

    async def close(self):
        pass


class _MixedClient:
    """First N requests succeed, then 429."""

    def __init__(self, *, succeed_count: int = 3):
        self._count = 0
        self._succeed_count = succeed_count

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self._count += 1
        if self._count <= self._succeed_count:
            return _FakeResponse(200)
        return _FakeResponse(429)

    async def close(self):
        pass


class _ErrorClient:
    """Every request raises an exception."""

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        raise ConnectionError("network failure")

    async def close(self):
        pass


_TARGET = Target(url="https://api.example.com")


# ------------------------------------------------------------------
# No rate limiting → finding produced
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestNoRateLimit:

    async def test_all_succeed_produces_finding(self):
        tester = RateLimitTester(http_client=_AlwaysSucceedClient())  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/login", method="POST")
        findings = await tester.test([rt], _TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "rate limit" in findings[0].title.lower()
        assert findings[0].cwe == 799

    async def test_finding_has_correct_module(self):
        tester = RateLimitTester(http_client=_AlwaysSucceedClient())  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/purchase", label="purchase")
        findings = await tester.test([rt], _TARGET)
        assert findings[0].module == "WaaaghLogic"
        assert "purchase" in findings[0].title

    async def test_burst_sends_correct_count(self):
        client = _AlwaysSucceedClient()
        tester = RateLimitTester(http_client=client)  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/otp", burst_size=15)
        await tester.test([rt], _TARGET)
        assert client.call_count == 15


# ------------------------------------------------------------------
# Rate limiting active → no finding
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestRateLimitEnforced:

    async def test_all_429_no_finding(self):
        tester = RateLimitTester(http_client=_AlwaysRateLimitClient())  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/login")
        findings = await tester.test([rt], _TARGET)
        assert findings == []

    async def test_mostly_blocked_no_finding(self):
        """Only 3/10 succeed → below 0.9 threshold → rate-limited."""
        tester = RateLimitTester(http_client=_MixedClient(succeed_count=3))  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/login", burst_size=10)
        findings = await tester.test([rt], _TARGET)
        assert findings == []


# ------------------------------------------------------------------
# Custom thresholds
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestCustomThreshold:

    async def test_low_threshold_stricter(self):
        """With threshold=0.5, 6/10 success is detected as *no* rate limit."""
        tester = RateLimitTester(http_client=_MixedClient(succeed_count=6))  # type: ignore[arg-type]
        rt = RateLimitTarget(
            url="https://api.example.com/transfer",
            burst_size=10,
            success_threshold=0.5,
        )
        findings = await tester.test([rt], _TARGET)
        assert len(findings) == 1

    async def test_high_threshold_lenient(self):
        """With threshold=1.0, only 100% success triggers finding."""
        tester = RateLimitTester(http_client=_MixedClient(succeed_count=9))  # type: ignore[arg-type]
        rt = RateLimitTarget(
            url="https://api.example.com/transfer",
            burst_size=10,
            success_threshold=1.0,
        )
        findings = await tester.test([rt], _TARGET)
        assert findings == []


# ------------------------------------------------------------------
# Multiple targets
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestMultipleTargets:

    async def test_multiple_targets_each_checked(self):
        tester = RateLimitTester(http_client=_AlwaysSucceedClient())  # type: ignore[arg-type]
        targets = [
            RateLimitTarget(url="https://api.example.com/login", label="login"),
            RateLimitTarget(url="https://api.example.com/otp", label="otp"),
        ]
        findings = await tester.test(targets, _TARGET)
        assert len(findings) == 2

    async def test_empty_targets_no_findings(self):
        tester = RateLimitTester(http_client=_AlwaysSucceedClient())  # type: ignore[arg-type]
        findings = await tester.test([], _TARGET)
        assert findings == []


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestErrorHandling:

    async def test_all_errors_no_finding(self):
        """When all requests error out, success_count=0 → rate_limit_enforced=True → no finding."""
        tester = RateLimitTester(http_client=_ErrorClient())  # type: ignore[arg-type]
        rt = RateLimitTarget(url="https://api.example.com/login", burst_size=5)
        findings = await tester.test([rt], _TARGET)
        assert findings == []


# ------------------------------------------------------------------
# Dataclass defaults
# ------------------------------------------------------------------

class TestRateLimitTargetDefaults:

    def test_defaults(self):
        rt = RateLimitTarget(url="https://example.com/api")
        assert rt.method == "POST"
        assert rt.body is None
        assert rt.headers is None
        assert rt.label == ""
        assert rt.burst_size == _DEFAULT_BURST
        assert rt.success_threshold == _DEFAULT_SUCCESS_THRESHOLD

    def test_custom_values(self):
        rt = RateLimitTarget(
            url="https://example.com/transfer",
            method="PUT",
            body={"amount": 100},
            label="fund transfer",
            burst_size=20,
            success_threshold=0.8,
        )
        assert rt.method == "PUT"
        assert rt.body == {"amount": 100}
        assert rt.burst_size == 20


class TestBurstResultDefaults:

    def test_defaults(self):
        rt = RateLimitTarget(url="https://example.com")
        br = BurstResult(target=rt)
        assert br.total_sent == 0
        assert br.success_count == 0
        assert br.rate_limited_count == 0
        assert br.error_count == 0
        assert br.status_codes == []
        assert br.rate_limit_enforced is False


class TestTesterDefaults:

    def test_default_concurrency(self):
        tester = RateLimitTester()
        assert tester.concurrency == _DEFAULT_CONCURRENCY

    def test_custom_concurrency(self):
        tester = RateLimitTester(concurrency=20)
        assert tester.concurrency == 20


class TestSetClient:

    def test_set_client_wires_in(self):
        tester = RateLimitTester()
        fake_client = _AlwaysSucceedClient()
        tester.set_client(fake_client)  # type: ignore[arg-type]
        assert tester._client is fake_client  # type: ignore[comparison-overlap]
        assert tester._owns_client is False
