"""Tests for krumpa.sneakygits.cors_checker — CORS misconfiguration detection."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, Severity, Target
from krumpa.sneakygits.cors_checker import CorsChecker


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class FakeHeaders(dict):
    """Case-insensitive header dict."""
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class FakeResponse:
    def __init__(self, headers: dict):
        self.headers = FakeHeaders(headers)
        self.status_code = 200
        self.content = b""
        self.text = ""


class FakeHttpClient:
    """
    Return different CORS headers depending on the Origin sent.
    ``origin_map`` maps an Origin value → response header dict.
    """

    def __init__(self, *, origin_map: dict[str, dict] | None = None,
                 default_headers: dict | None = None):
        self._origin_map = origin_map or {}
        self._default = default_headers or {}
        self.requests: list[dict] = []

    async def get(self, url, *, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        self.requests.append({"url": url, "origin": origin})
        resp_headers = self._origin_map.get(origin, self._default)
        return FakeResponse(resp_headers)

    async def close(self):
        pass


# ------------------------------------------------------------------
# Tests — no CORS at all (safe)
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestNoCors:

    async def test_no_cors_headers_no_findings(self):
        """Server with no CORS headers — nothing to report."""
        client = FakeHttpClient(default_headers={})
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com/v1"))
        assert findings == []


# ------------------------------------------------------------------
# Tests — wildcard + credentials
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestWildcardCredentials:

    async def test_wildcard_with_credentials(self):
        client = FakeHttpClient(default_headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        wildcard = [f for f in findings if "wildcard" in f.title.lower()]
        assert len(wildcard) == 1
        assert wildcard[0].severity == Severity.HIGH

    async def test_wildcard_without_credentials_no_finding(self):
        client = FakeHttpClient(default_headers={
            "Access-Control-Allow-Origin": "*",
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        wildcard = [f for f in findings if "wildcard" in f.title.lower()]
        assert len(wildcard) == 0


# ------------------------------------------------------------------
# Tests — origin reflection
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestOriginReflection:

    async def test_reflects_evil_origin_with_credentials(self):
        evil = "https://attacker.example.com"
        client = FakeHttpClient(origin_map={
            evil: {
                "Access-Control-Allow-Origin": evil,
                "Access-Control-Allow-Credentials": "true",
            },
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        reflection = [f for f in findings if "reflection" in f.title.lower()]
        assert len(reflection) == 1
        assert reflection[0].severity == Severity.HIGH

    async def test_reflects_evil_origin_without_credentials(self):
        evil = "https://attacker.example.com"
        client = FakeHttpClient(origin_map={
            evil: {
                "Access-Control-Allow-Origin": evil,
            },
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        reflection = [f for f in findings if "reflection" in f.title.lower()]
        assert len(reflection) == 1
        assert reflection[0].severity == Severity.MEDIUM

    async def test_does_not_reflect_evil_origin(self):
        evil = "https://attacker.example.com"
        client = FakeHttpClient(origin_map={
            evil: {"Access-Control-Allow-Origin": "https://api.example.com"},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        reflection = [f for f in findings if "reflection" in f.title.lower()]
        assert len(reflection) == 0


# ------------------------------------------------------------------
# Tests — null origin
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestNullOrigin:

    async def test_null_origin_allowed_with_credentials(self):
        client = FakeHttpClient(origin_map={
            "null": {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            },
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        null_f = [f for f in findings if "null" in f.title.lower()]
        assert len(null_f) == 1
        assert null_f[0].severity == Severity.HIGH

    async def test_null_origin_allowed_without_credentials(self):
        client = FakeHttpClient(origin_map={
            "null": {"Access-Control-Allow-Origin": "null"},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        null_f = [f for f in findings if "null" in f.title.lower()]
        assert len(null_f) == 1
        assert null_f[0].severity == Severity.MEDIUM

    async def test_null_origin_rejected(self):
        client = FakeHttpClient(origin_map={
            "null": {},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        null_f = [f for f in findings if "null" in f.title.lower()]
        assert len(null_f) == 0


# ------------------------------------------------------------------
# Tests — prefix/substring bypass
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestPrefixBypass:

    async def test_prefix_match_detected(self):
        evil = "https://api.example.com.evil.com"
        client = FakeHttpClient(origin_map={
            evil: {"Access-Control-Allow-Origin": evil},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com/v1"))
        prefix = [f for f in findings if "prefix" in f.title.lower() or "substring" in f.title.lower()]
        assert len(prefix) == 1
        assert prefix[0].severity == Severity.HIGH

    async def test_prefix_not_trusted(self):
        evil = "https://api.example.com.evil.com"
        client = FakeHttpClient(origin_map={
            evil: {},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com/v1"))
        prefix = [f for f in findings if "prefix" in f.title.lower()]
        assert len(prefix) == 0


# ------------------------------------------------------------------
# Tests — metadata
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestFindingMetadata:

    async def test_findings_have_cors_tag(self):
        evil = "https://attacker.example.com"
        client = FakeHttpClient(origin_map={
            evil: {
                "Access-Control-Allow-Origin": evil,
                "Access-Control-Allow-Credentials": "true",
            },
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        for f in findings:
            assert "cors" in f.tags

    async def test_findings_have_cwe(self):
        evil = "https://attacker.example.com"
        client = FakeHttpClient(origin_map={
            evil: {"Access-Control-Allow-Origin": evil},
        })
        checker = CorsChecker(http_client=client)
        findings = await checker.check(Target(url="https://api.example.com"))
        for f in findings:
            assert f.cwe == 942


# ------------------------------------------------------------------
# Tests — error handling
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestErrorHandling:

    async def test_http_error_returns_empty(self):
        class FailClient:
            async def get(self, url, **kw):
                import httpx
                raise httpx.ConnectError("refused")
            async def close(self):
                pass

        checker = CorsChecker(http_client=FailClient())
        findings = await checker.check(Target(url="https://api.example.com"))
        assert findings == []
