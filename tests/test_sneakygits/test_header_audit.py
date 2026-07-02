"""Tests for krumpa.sneakygits.header_audit — security header auditor."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.sneakygits.header_audit import (
    HeaderAuditor,
    SECURITY_HEADERS,
    _validate_hsts_max_age,
    _validate_hsts_subdomains,
    _validate_xcto,
    _validate_xfo,
    _validate_referrer_policy,
    _validate_csp_present,
)


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class FakeHeaders(dict):
    """dict subclass with case-insensitive .get() matching httpx.Headers."""
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
    """Returns a controllable response (no network)."""
    def __init__(self, headers: dict):
        self._headers = headers

    async def get(self, url, **kw):
        return FakeResponse(self._headers)

    async def close(self):
        pass


# ------------------------------------------------------------------
# Validator unit tests
# ------------------------------------------------------------------

class TestValidateHsts:

    def test_good_max_age(self):
        ok, _ = _validate_hsts_max_age("max-age=31536000; includeSubDomains")
        assert ok

    def test_short_max_age(self):
        ok, msg = _validate_hsts_max_age("max-age=3600")
        assert not ok
        assert "31536000" in msg

    def test_missing_max_age(self):
        ok, msg = _validate_hsts_max_age("includeSubDomains")
        assert not ok
        assert "missing" in msg.lower()

    def test_include_subdomains_present(self):
        ok, _ = _validate_hsts_subdomains("max-age=31536000; includeSubDomains")
        assert ok

    def test_include_subdomains_absent(self):
        ok, msg = _validate_hsts_subdomains("max-age=31536000")
        assert not ok


class TestValidateXcto:

    def test_nosniff(self):
        ok, _ = _validate_xcto("nosniff")
        assert ok

    def test_wrong_value(self):
        ok, msg = _validate_xcto("sniff")
        assert not ok
        assert "nosniff" in msg


class TestValidateXfo:

    def test_deny(self):
        ok, _ = _validate_xfo("DENY")
        assert ok

    def test_sameorigin(self):
        ok, _ = _validate_xfo("SAMEORIGIN")
        assert ok

    def test_allow_from(self):
        ok, _ = _validate_xfo("ALLOW-FROM https://example.com")
        assert not ok


class TestValidateReferrerPolicy:

    def test_strict_origin(self):
        ok, _ = _validate_referrer_policy("strict-origin-when-cross-origin")
        assert ok

    def test_no_referrer(self):
        ok, _ = _validate_referrer_policy("no-referrer")
        assert ok

    def test_unsafe_url(self):
        ok, _ = _validate_referrer_policy("unsafe-url")
        assert not ok


class TestValidateCsp:

    def test_good_csp(self):
        ok, _ = _validate_csp_present("default-src 'self'; script-src 'self'")
        assert ok

    def test_unsafe_inline(self):
        ok, msg = _validate_csp_present("default-src 'self'; script-src 'unsafe-inline'")
        assert not ok
        assert "unsafe-inline" in msg

    def test_unsafe_eval(self):
        ok, msg = _validate_csp_present("default-src 'self'; script-src 'unsafe-eval'")
        assert not ok
        assert "unsafe-eval" in msg

    def test_unsafe_inline_with_nonce_ok(self):
        ok, _ = _validate_csp_present("script-src 'nonce-abc123' 'unsafe-inline'")
        assert ok

    def test_unsafe_inline_with_strict_dynamic_ok(self):
        ok, _ = _validate_csp_present("script-src 'strict-dynamic' 'unsafe-inline'")
        assert ok


# ------------------------------------------------------------------
# HeaderAuditor integration tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestHeaderAuditor:

    async def test_all_headers_present_no_findings(self):
        """When all required headers are present and correct, no findings."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
        auditor = HeaderAuditor(http_client=FakeHttpClient(headers))
        findings = await auditor.audit(Target(url="https://example.com"))
        assert len(findings) == 0

    async def test_no_headers_produces_findings(self):
        """When no security headers are present, we get findings for each required one."""
        auditor = HeaderAuditor(http_client=FakeHttpClient({}))
        findings = await auditor.audit(Target(url="https://example.com"))
        # 6 required headers should produce findings
        required_count = sum(1 for h in SECURITY_HEADERS if h.required)
        assert len(findings) >= required_count

    async def test_missing_hsts_finding(self):
        auditor = HeaderAuditor(http_client=FakeHttpClient({}))
        findings = await auditor.audit(Target(url="https://example.com"))
        hsts_findings = [f for f in findings if "Strict-Transport-Security" in f.title]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.MEDIUM

    async def test_missing_csp_finding(self):
        auditor = HeaderAuditor(http_client=FakeHttpClient({}))
        findings = await auditor.audit(Target(url="https://example.com"))
        csp_findings = [f for f in findings if "Content-Security-Policy" in f.title]
        assert len(csp_findings) == 1

    async def test_weak_hsts_max_age(self):
        headers = {
            "Strict-Transport-Security": "max-age=3600",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        auditor = HeaderAuditor(http_client=FakeHttpClient(headers))
        findings = await auditor.audit(Target(url="https://example.com"))
        weak = [f for f in findings if "Weak" in f.title and "Strict-Transport" in f.title]
        assert len(weak) >= 1

    async def test_server_header_leak(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Server": "nginx/1.21.3",
        }
        auditor = HeaderAuditor(http_client=FakeHttpClient(headers))
        findings = await auditor.audit(Target(url="https://example.com"))
        leak = [f for f in findings if "Server" in f.title and "disclosure" in f.title]
        assert len(leak) == 1
        assert "nginx/1.21.3" in leak[0].evidence

    async def test_x_powered_by_leak(self):
        headers = {
            "X-Powered-By": "Express 4.18.2",
        }
        auditor = HeaderAuditor(http_client=FakeHttpClient(headers))
        findings = await auditor.audit(Target(url="https://example.com"))
        leak = [f for f in findings if "X-Powered-By" in f.title]
        assert len(leak) == 1

    async def test_findings_have_tags(self):
        auditor = HeaderAuditor(http_client=FakeHttpClient({}))
        findings = await auditor.audit(Target(url="https://example.com"))
        for f in findings:
            assert "headers" in f.tags

    async def test_findings_have_remediation(self):
        auditor = HeaderAuditor(http_client=FakeHttpClient({}))
        findings = await auditor.audit(Target(url="https://example.com"))
        for f in findings:
            assert f.remediation != ""

    async def test_http_error_returns_empty(self):
        """If the HTTP request fails, no findings (not a crash)."""
        class FailClient:
            async def get(self, url, **kw):
                import httpx
                raise httpx.ConnectError("refused")
            async def close(self):
                pass

        auditor = HeaderAuditor(http_client=FailClient())
        findings = await auditor.audit(Target(url="https://example.com"))
        assert findings == []
