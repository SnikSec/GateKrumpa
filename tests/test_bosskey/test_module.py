"""Tests for the BossKeyModule orchestrator."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.bosskey.auth_probe import AuthEndpoint
from krumpa.bosskey.module import BossKeyModule


# ------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------

class _FakeSessionAnalyzer:
    def __init__(self, cookie_findings=None, token_findings=None):
        self._cookie_findings = cookie_findings or []
        self._token_findings = token_findings or []

    def analyse_cookies(self, headers, target, *, is_https=True):
        return list(self._cookie_findings)

    def analyse_tokens(self, values, target):
        return list(self._token_findings)


class _FakeAuthProbe:
    def __init__(self, findings=None):
        self._findings = findings or []
        self.probed_endpoints: list[str] = []

    async def probe(self, endpoint, target):
        self.probed_endpoints.append(endpoint.url)
        return list(self._findings)


class _NoopAsync:
    """Stub that returns [] for any async method call."""
    def __getattr__(self, name):
        async def _noop(*a, **kw):
            return []
        return _noop


class _NoopSync:
    """Stub that returns [] for any sync method call."""
    def __getattr__(self, name):
        def _noop(*a, **kw):
            return []
        return _noop


def _make_module(
    cookie_findings=None,
    token_findings=None,
    probe_findings=None,
    login_endpoints=None,
) -> BossKeyModule:
    mod = BossKeyModule(login_endpoints=login_endpoints)
    mod._session_analyzer = _FakeSessionAnalyzer(cookie_findings, token_findings)
    mod._auth_probe = _FakeAuthProbe(probe_findings)
    # Neutralise sub-components added in Phase 1-4
    mod._csrf_checker = _NoopAsync()
    mod._oauth2_analyzer = _NoopAsync()
    mod._session_fixation = _NoopAsync()
    mod._password_policy = _NoopAsync()
    mod._session_timeout = _NoopAsync()
    mod._lockout_tester = _NoopAsync()
    mod._jwt_tester = _NoopSync()
    mod._rbac_builder = _NoopAsync()
    # Phase 2 sub-components
    mod._auth_scheme_enforcer = _NoopAsync()
    mod._password_reset = _NoopAsync()
    mod._credential_transport = _NoopAsync()
    mod._token_storage = _NoopAsync()
    mod._registration_tester = _NoopAsync()
    mod._mfa_tester = _NoopAsync()
    return mod


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestBossKeyModule:

    async def test_empty_context_no_findings(self):
        mod = _make_module()
        ctx = ScanContext()
        findings = await mod.run(ctx)
        assert findings == []

    async def test_cookie_findings_returned(self):
        f = Finding(title="Missing Secure", severity=Severity.MEDIUM)
        mod = _make_module(cookie_findings=[f])
        target = Target(
            url="https://example.com",
            metadata={"set_cookie_headers": ["session=abc"]},
        )
        ctx = ScanContext(targets=[target])
        findings = await mod.run(ctx)
        assert len(findings) == 1
        assert findings[0].title == "Missing Secure"

    async def test_token_findings_returned(self):
        f = Finding(title="JWT alg none", severity=Severity.CRITICAL)
        mod = _make_module(token_findings=[f])
        target = Target(url="https://example.com")
        ctx = ScanContext(targets=[target], auth_tokens={"bearer": "eyJhbGciOiJub25lIn0..."})
        findings = await mod.run(ctx)
        assert any("JWT" in fi.title for fi in findings)

    async def test_explicit_login_endpoints_probed(self):
        probe_finding = Finding(title="Default creds", severity=Severity.CRITICAL)
        ep = AuthEndpoint(url="https://example.com/login")
        mod = _make_module(probe_findings=[probe_finding], login_endpoints=[ep])
        ctx = ScanContext()
        findings = await mod.run(ctx)
        assert any("Default creds" in fi.title for fi in findings)
        assert "https://example.com/login" in mod._auth_probe.probed_endpoints

    async def test_auto_detects_login_endpoints(self):
        mod = _make_module()
        ctx = ScanContext(targets=[
            Target(url="https://example.com/api/login"),
            Target(url="https://example.com/about"),
        ])
        endpoints = mod._detect_login_endpoints(ctx)
        urls = [e.url for e in endpoints]
        assert "https://example.com/api/login" in urls
        assert "https://example.com/about" not in urls

    async def test_auto_detect_includes_auth_paths(self):
        mod = _make_module()
        ctx = ScanContext(targets=[
            Target(url="https://example.com/auth"),
            Target(url="https://example.com/token"),
            Target(url="https://example.com/signin"),
            Target(url="https://example.com/oauth"),
        ])
        endpoints = mod._detect_login_endpoints(ctx)
        urls = [e.url for e in endpoints]
        assert len(urls) == 4

    async def test_findings_registered_on_module(self):
        f = Finding(title="test", severity=Severity.LOW)
        mod = _make_module(cookie_findings=[f])
        target = Target(
            url="https://example.com",
            metadata={"set_cookie_headers": ["x=y"]},
        )
        ctx = ScanContext(targets=[target])
        await mod.run(ctx)
        assert len(mod.findings) == 1
        assert mod.findings[0].module == "BossKey"

    async def test_module_attributes(self):
        mod = BossKeyModule()
        assert mod.name == "BossKey"
        assert "Auth" in mod.description

    async def test_analyses_authorization_header(self):
        f = Finding(title="JWT issue", severity=Severity.HIGH)
        mod = _make_module(token_findings=[f])
        target = Target(
            url="https://example.com",
            headers={"Authorization": "Bearer eyJhbGciOi..."},
        )
        ctx = ScanContext(targets=[target])
        findings = await mod.run(ctx)
        assert len(findings) == 1
