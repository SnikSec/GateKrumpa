"""Tests for IdempotencyChecker — duplicate submission and race conditions."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.waaaghlogic.idempotency_checker import IdempotencyChecker


# ------------------------------------------------------------------
# Fake HTTP
# ------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "ok"):
        self.status_code = status_code
        self.text = text


class _CountingClient:
    """Returns success for the first N calls, then a different status."""

    def __init__(self, *, succeed_count: int = 999, success_status: int = 200, fail_status: int = 409):
        self._count = 0
        self._succeed_count = succeed_count
        self._success_status = success_status
        self._fail_status = fail_status

    async def request(self, method, url, *, json_body=None, **kw):
        self._count += 1
        if self._count <= self._succeed_count:
            return _FakeResponse(self._success_status, "ok")
        return _FakeResponse(self._fail_status, "conflict")

    async def close(self):
        pass


class _AlwaysSucceedClient:
    """Every request returns 200."""
    async def request(self, method, url, *, json_body=None, **kw):
        return _FakeResponse(200, "ok")

    async def close(self):
        pass


class _AlwaysFailClient:
    """Every request returns 500."""
    async def request(self, method, url, *, json_body=None, **kw):
        return _FakeResponse(500, "error")

    async def close(self):
        pass


class _VaryingBodyClient:
    """Returns 200 but with different bodies each time."""
    def __init__(self):
        self._count = 0

    async def request(self, method, url, *, json_body=None, **kw):
        self._count += 1
        return _FakeResponse(200, f"response_{self._count}")

    async def close(self):
        pass


def _target() -> Target:
    return Target(url="https://example.com")


# ------------------------------------------------------------------
# Duplicate submission
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestDuplicateSubmission:

    async def test_detects_duplicate_accepted(self):
        client = _AlwaysSucceedClient()
        checker = IdempotencyChecker(http_client=client, concurrency=2)
        findings = await checker.check("https://example.com/pay", _target())
        dup_findings = [f for f in findings if "duplicate" in f.title.lower()]
        assert len(dup_findings) == 1
        assert dup_findings[0].severity == Severity.MEDIUM

    async def test_no_finding_when_second_rejected(self):
        client = _CountingClient(succeed_count=1, fail_status=409)
        checker = IdempotencyChecker(http_client=client, concurrency=2)
        findings = await checker.check("https://example.com/pay", _target())
        dup_findings = [f for f in findings if "duplicate" in f.title.lower()]
        assert dup_findings == []

    async def test_no_finding_when_both_fail(self):
        client = _AlwaysFailClient()
        checker = IdempotencyChecker(http_client=client, concurrency=2)
        findings = await checker.check("https://example.com/pay", _target())
        dup_findings = [f for f in findings if "duplicate" in f.title.lower()]
        assert dup_findings == []


# ------------------------------------------------------------------
# Race conditions
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestRaceCondition:

    async def test_detects_race_when_all_succeed(self):
        client = _AlwaysSucceedClient()
        checker = IdempotencyChecker(http_client=client, concurrency=5)
        findings = await checker.check("https://example.com/transfer", _target())
        race_findings = [f for f in findings if "race condition" in f.title.lower()]
        assert len(race_findings) == 1
        assert race_findings[0].severity == Severity.HIGH

    async def test_no_race_when_only_one_succeeds(self):
        client = _CountingClient(succeed_count=1)
        checker = IdempotencyChecker(http_client=client, concurrency=5)
        findings = await checker.check("https://example.com/transfer", _target())
        race_findings = [f for f in findings if "race condition" in f.title.lower()]
        assert race_findings == []

    async def test_inconsistent_bodies_flagged(self):
        client = _VaryingBodyClient()
        checker = IdempotencyChecker(http_client=client, concurrency=3)
        findings = await checker.check("https://example.com/data", _target())
        incon_findings = [f for f in findings if "inconsistent" in f.title.lower()]
        assert len(incon_findings) == 1

    async def test_concurrency_parameter_respected(self):
        """The number of concurrent requests matches the concurrency setting."""
        call_count = 0

        class _TrackingClient:
            async def request(self, method, url, *, json_body=None, **kw):
                nonlocal call_count
                call_count += 1
                return _FakeResponse(200)
            async def close(self):
                pass

        checker = IdempotencyChecker(http_client=_TrackingClient(), concurrency=7)
        await checker.check("https://example.com/action", _target())
        # 2 sequential (duplicate test) + 7 concurrent (race test)
        assert call_count == 9


# ------------------------------------------------------------------
# Custom expected status
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestCustomStatus:

    async def test_uses_custom_expected_status(self):
        """Duplicate detection respects the caller's expected_status."""
        class _Status201Client:
            async def request(self, method, url, *, json_body=None, **kw):
                return _FakeResponse(201, "created")
            async def close(self):
                pass

        checker = IdempotencyChecker(http_client=_Status201Client(), concurrency=2)
        findings = await checker.check(
            "https://example.com/create", _target(), expected_status=201,
        )
        dup_findings = [f for f in findings if "duplicate" in f.title.lower()]
        assert len(dup_findings) == 1
