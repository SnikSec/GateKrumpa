"""Tests for AuthProbe — credential testing and rate-limit detection."""

from __future__ import annotations

from typing import Any

import pytest

from krumpa.core import Severity, Target
from krumpa.bosskey.auth_probe import AuthEndpoint, AuthProbe


# ------------------------------------------------------------------
# Fake HTTP client
# ------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeHttpClient:
    """Records requests and returns configurable responses."""

    def __init__(
        self,
        *,
        default_status: int = 401,
        default_body: str = '{"error": "invalid credentials"}',
        accept_creds: dict[tuple[str, str], tuple[int, str]] | None = None,
        block_after: int | None = None,
    ):
        self.default_status = default_status
        self.default_body = default_body
        self.accept_creds = accept_creds or {}
        self.block_after = block_after
        self.request_log: list[dict] = []
        self._attempt_count = 0

    async def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        **kw,
    ) -> _FakeResponse:
        self.request_log.append({"method": method, "url": url, "json_body": json_body})
        self._attempt_count += 1

        if self.block_after and self._attempt_count > self.block_after:
            return _FakeResponse(status_code=429, text='{"error": "rate limited"}')

        if json_body:
            key = (json_body.get("username", ""), json_body.get("password", ""))
            if key in self.accept_creds:
                status, body = self.accept_creds[key]
                return _FakeResponse(status_code=status, text=body)

        return _FakeResponse(status_code=self.default_status, text=self.default_body)

    async def close(self) -> None:
        pass


def _target() -> Target:
    return Target(url="https://example.com")


def _endpoint(url: str = "https://example.com/login") -> AuthEndpoint:
    return AuthEndpoint(url=url)


# ------------------------------------------------------------------
# Default credentials
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestDefaultCreds:

    async def test_detects_accepted_default_creds(self):
        client = _FakeHttpClient(
            accept_creds={("admin", "admin"): (200, '{"token": "abc"}')},
        )
        probe = AuthProbe(http_client=client, credentials=[("admin", "admin")])
        findings = await probe.probe(_endpoint(), _target())
        cred_findings = [f for f in findings if "Default credentials" in f.title]
        assert len(cred_findings) >= 1
        assert cred_findings[0].severity == Severity.CRITICAL

    async def test_no_finding_when_all_rejected(self):
        client = _FakeHttpClient()
        probe = AuthProbe(http_client=client, credentials=[("admin", "admin")])
        findings = await probe.probe(_endpoint(), _target())
        cred_findings = [f for f in findings if "Default credentials" in f.title]
        assert cred_findings == []

    async def test_evidence_contains_credentials(self):
        client = _FakeHttpClient(
            accept_creds={("root", "toor"): (200, '{"session": "xyz"}')},
        )
        probe = AuthProbe(http_client=client, credentials=[("root", "toor")])
        findings = await probe.probe(_endpoint(), _target())
        cred_findings = [f for f in findings if "Default credentials" in f.title]
        assert "root" in cred_findings[0].evidence


# ------------------------------------------------------------------
# Rate-limiting
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestRateLimiting:

    async def test_no_rate_limit_produces_finding(self):
        client = _FakeHttpClient()  # never returns 429
        probe = AuthProbe(http_client=client, credentials=[], rate_limit_threshold=3)
        findings = await probe.probe(_endpoint(), _target())
        rl_findings = [f for f in findings if "rate-limit" in f.title.lower()]
        assert len(rl_findings) == 1
        assert rl_findings[0].severity == Severity.HIGH

    async def test_rate_limit_detected_no_finding(self):
        client = _FakeHttpClient(block_after=2)  # blocks after 2 attempts
        probe = AuthProbe(http_client=client, credentials=[], rate_limit_threshold=5)
        findings = await probe.probe(_endpoint(), _target())
        rl_findings = [f for f in findings if "rate-limit" in f.title.lower()]
        assert rl_findings == []


# ------------------------------------------------------------------
# User enumeration
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestUserEnumeration:

    async def test_detects_different_status_codes(self):
        """If 'admin' returns 401 but random user returns 404 → enumeration."""
        class _EnumClient:
            async def request(self, method, url, *, json_body=None, **kw):
                user = json_body.get("username", "")
                if user == "admin":
                    return _FakeResponse(401, '{"error": "wrong password"}')
                return _FakeResponse(404, '{"error": "user not found"}')
            async def close(self):
                pass

        probe = AuthProbe(http_client=_EnumClient(), credentials=[], rate_limit_threshold=0)
        findings = await probe.probe(_endpoint(), _target())
        enum_findings = [f for f in findings if "enumeration" in f.title.lower()]
        assert len(enum_findings) == 1
        assert enum_findings[0].severity == Severity.MEDIUM

    async def test_no_enumeration_when_same_response(self):
        client = _FakeHttpClient()  # same 401 for everything
        probe = AuthProbe(http_client=client, credentials=[], rate_limit_threshold=0)
        findings = await probe.probe(_endpoint(), _target())
        enum_findings = [f for f in findings if "enumeration" in f.title.lower()]
        assert enum_findings == []

    async def test_detects_different_body(self):
        """Same status code but different error message → enumeration."""
        class _BodyEnumClient:
            async def request(self, method, url, *, json_body=None, **kw):
                user = json_body.get("username", "")
                if user == "admin":
                    return _FakeResponse(401, '{"error": "invalid password"}')
                return _FakeResponse(401, '{"error": "user not found"}')
            async def close(self):
                pass

        probe = AuthProbe(http_client=_BodyEnumClient(), credentials=[], rate_limit_threshold=0)
        findings = await probe.probe(_endpoint(), _target())
        enum_findings = [f for f in findings if "enumeration" in f.title.lower()]
        assert len(enum_findings) == 1


# ------------------------------------------------------------------
# LoginResult / helpers
# ------------------------------------------------------------------

class TestBodiesDiffer:

    def test_identical(self):
        assert AuthProbe._bodies_differ("hello world", "hello world") is False

    def test_whitespace_normalised(self):
        assert AuthProbe._bodies_differ("hello  world", "hello world") is False

    def test_case_insensitive(self):
        assert AuthProbe._bodies_differ("Hello", "hello") is False

    def test_different(self):
        assert AuthProbe._bodies_differ("error: wrong password", "error: no such user") is True
