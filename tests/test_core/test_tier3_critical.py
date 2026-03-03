"""
Tests for Tier 3 Critical features:
  1. BossKey — CSRF protection audit
  2. BossKey — OAuth2 flow analysis
  3. GrotAssault — XXE payloads
  4. GrotAssault — SSRF payloads
  5. OpenKrump — BOLA test generation
  6. WaaaghGate — Baseline comparison
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from krumpa.core import Finding, Severity, Target, ScanContext


# =====================================================================
# Shared fakes
# =====================================================================

@dataclass
class FakeResponse:
    """Minimal fake HTTP response for testing."""
    status_code: int = 200
    text: str = ""
    _headers: Dict[str, str] = field(default_factory=dict)

    @property
    def headers(self) -> Dict[str, str]:
        return self._headers


class FakeHttpClient:
    """Fake HttpClient that returns preconfigured responses."""

    def __init__(self, responses: Optional[List[FakeResponse]] = None) -> None:
        self._responses = list(responses or [])
        self._call_index = 0
        self.requests: List[dict] = []

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return await self.request("GET", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> FakeResponse:
        self.requests.append({
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body,
            "params": params,
        })
        if self._responses:
            resp = self._responses[self._call_index % len(self._responses)]
            self._call_index += 1
            return resp
        return FakeResponse()

    async def close(self) -> None:
        pass


# =====================================================================
# 1. CSRF Checker Tests
# =====================================================================

class TestCsrfChecker:
    """Tests for CsrfChecker."""

    def _make_checker(self, client: FakeHttpClient):
        from krumpa.bosskey.csrf_checker import CsrfChecker
        c = CsrfChecker(http_client=client)
        return c

    @pytest.mark.asyncio
    async def test_no_csrf_token_in_form(self):
        """Flag forms without CSRF tokens."""
        html = (
            '<html><body>'
            '<form method="POST" action="/submit">'
            '<input type="text" name="username">'
            '<input type="submit">'
            '</form>'
            '</body></html>'
        )
        client = FakeHttpClient([
            FakeResponse(200, html, {"content-type": "text/html"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/login", method="GET")
        findings = await checker.check(target)
        csrf_findings = [f for f in findings if "csrf" in f.tags or "CSRF" in f.title.lower()]
        assert len(csrf_findings) >= 1
        assert any("No CSRF token" in f.title for f in csrf_findings)

    @pytest.mark.asyncio
    async def test_csrf_token_present_in_form(self):
        """No finding when CSRF token is present."""
        html = (
            '<html><body>'
            '<form method="POST" action="/submit">'
            '<input type="hidden" name="csrf_token" value="abc123">'
            '<input type="text" name="data">'
            '</form>'
            '</body></html>'
        )
        client = FakeHttpClient([
            FakeResponse(200, html, {"content-type": "text/html"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/submit", method="GET")
        findings = await checker.check(target)
        token_findings = [f for f in findings if "missing-token" in f.tags]
        assert len(token_findings) == 0

    @pytest.mark.asyncio
    async def test_csrf_meta_tag_accepted(self):
        """Recognise CSRF token in meta tags."""
        html = (
            '<html><head>'
            '<meta name="csrf-token" content="xyz789">'
            '</head><body>'
            '<form method="POST" action="/submit">'
            '<input type="text" name="data">'
            '</form>'
            '</body></html>'
        )
        client = FakeHttpClient([
            FakeResponse(200, html, {"content-type": "text/html"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/page", method="GET")
        findings = await checker.check(target)
        missing = [f for f in findings if "missing-token" in f.tags]
        assert len(missing) == 0

    @pytest.mark.asyncio
    async def test_non_html_skipped(self):
        """Non-HTML responses should not produce CSRF form findings."""
        client = FakeHttpClient([
            FakeResponse(200, '{"key":"value"}', {"content-type": "application/json"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/api", method="GET")
        findings = await checker.check(target)
        form_findings = [f for f in findings if "missing-token" in f.tags]
        assert len(form_findings) == 0

    @pytest.mark.asyncio
    async def test_cross_origin_acceptance_flagged(self):
        """Flag endpoints accepting cross-origin requests."""
        client = FakeHttpClient([
            FakeResponse(200, "ok"),  # request without headers
            FakeResponse(200, "ok"),  # X-CSRF-Token
            FakeResponse(200, "ok"),  # X-XSRF-TOKEN
            FakeResponse(200, "ok"),  # X-Requested-With
            FakeResponse(200, "ok"),  # cross-origin
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/api/action", method="POST")
        findings = await checker.check(target)
        cross_origin = [f for f in findings if "cross-origin" in f.tags]
        assert len(cross_origin) >= 1

    @pytest.mark.asyncio
    async def test_get_endpoint_skips_header_check(self):
        """GET endpoints should not be tested for header-based CSRF."""
        client = FakeHttpClient([
            FakeResponse(200, "<html></html>", {"content-type": "text/html"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/data", method="GET")
        findings = await checker.check(target)
        header_findings = [f for f in findings if "header-check" in f.tags or "cross-origin" in f.tags]
        assert len(header_findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_forms_counted(self):
        """Multiple unprotected forms should be counted."""
        html = (
            '<html><body>'
            '<form method="POST" action="/a"><input name="x"></form>'
            '<form method="POST" action="/b"><input name="y"></form>'
            '<form method="PUT" action="/c"><input name="z"></form>'
            '</body></html>'
        )
        client = FakeHttpClient([
            FakeResponse(200, html, {"content-type": "text/html"}),
        ])
        checker = self._make_checker(client)
        target = Target(url="https://example.com/page", method="GET")
        findings = await checker.check(target)
        missing = [f for f in findings if "missing-token" in f.tags]
        assert len(missing) == 1
        assert "3 state-changing form(s)" in missing[0].description


# =====================================================================
# 2. OAuth2 Analyzer Tests
# =====================================================================

class TestOAuth2Analyzer:
    """Tests for OAuth2Analyzer."""

    def _make_analyzer(self, client: FakeHttpClient):
        from krumpa.bosskey.oauth2_analyzer import OAuth2Analyzer
        a = OAuth2Analyzer(http_client=client)
        return a

    def _oidc_config(self, **overrides) -> dict:
        base = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
        base.update(overrides)
        return base

    @pytest.mark.asyncio
    async def test_implicit_grant_flagged(self):
        """Flag implicit grant (response_type=token)."""
        config = self._oidc_config(response_types_supported=["code", "token"])
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        implicit = [f for f in findings if "implicit-grant" in f.tags]
        assert len(implicit) == 1
        assert implicit[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_pkce_flagged(self):
        """Flag missing PKCE support."""
        config = self._oidc_config(code_challenge_methods_supported=[])
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        pkce = [f for f in findings if "no-pkce" in f.tags]
        assert len(pkce) == 1

    @pytest.mark.asyncio
    async def test_pkce_plain_only_flagged(self):
        """Flag PKCE with only 'plain' method."""
        config = self._oidc_config(code_challenge_methods_supported=["plain"])
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        pkce_plain = [f for f in findings if "pkce-plain" in f.tags]
        assert len(pkce_plain) == 1

    @pytest.mark.asyncio
    async def test_password_grant_flagged(self):
        """Flag ROPC grant type."""
        config = self._oidc_config(
            grant_types_supported=["authorization_code", "password"],
        )
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        pw = [f for f in findings if "password-grant" in f.tags]
        assert len(pw) == 1

    @pytest.mark.asyncio
    async def test_dangerous_scopes_flagged(self):
        """Flag overly broad scopes like 'admin' or '*'."""
        config = self._oidc_config(scopes_supported=["openid", "admin", "*"])
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        scope = [f for f in findings if "scope-overgranting" in f.tags]
        assert len(scope) == 1

    @pytest.mark.asyncio
    async def test_token_endpoint_http_flagged(self):
        """Flag token endpoint over plain HTTP."""
        config = self._oidc_config(token_endpoint="http://auth.example.com/token")
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        tls = [f for f in findings if "no-tls" in f.tags]
        assert len(tls) == 1
        assert tls[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_secure_config_no_findings(self):
        """A properly configured OAuth2 server should not produce findings."""
        config = self._oidc_config()
        # Discovery + authorize endpoint probe (returns 400 no client_id)
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
            FakeResponse(400, "invalid_client"),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        # Only potential low-severity or zero findings
        high_or_above = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(high_or_above) == 0

    @pytest.mark.asyncio
    async def test_no_discovery_no_findings(self):
        """If no .well-known endpoint found, gracefully return empty."""
        client = FakeHttpClient([
            FakeResponse(404, "not found"),
            FakeResponse(404, "not found"),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://example.com/api")
        findings = await analyzer.analyze(target)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_metadata_from_target(self):
        """OAuth2 config provided via target metadata."""
        config = self._oidc_config(response_types_supported=["token"])
        client = FakeHttpClient([
            FakeResponse(404, "not found"),
            FakeResponse(404, "not found"),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(
            url="https://example.com/",
            metadata={"oauth2_config": config},
        )
        findings = await analyzer.analyze(target)
        implicit = [f for f in findings if "implicit-grant" in f.tags]
        assert len(implicit) == 1

    @pytest.mark.asyncio
    async def test_client_auth_none_flagged(self):
        """Flag token_endpoint_auth_methods including 'none'."""
        config = self._oidc_config(
            token_endpoint_auth_methods_supported=["none", "client_secret_basic"],
        )
        client = FakeHttpClient([
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
            FakeResponse(400, "invalid_client"),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        auth_none = [f for f in findings if "client-auth-none" in f.tags]
        assert len(auth_none) == 1

    @pytest.mark.asyncio
    async def test_open_redirect_flagged(self):
        """Flag redirect_uri not validated."""
        config = self._oidc_config()
        client = FakeHttpClient([
            # Discovery
            FakeResponse(200, json.dumps(config), {"content-type": "application/json"}),
            # Authorize probe — redirects to evil domain
            FakeResponse(302, "", {"location": "https://evil-attacker.com/callback?code=xyz"}),
        ])
        analyzer = self._make_analyzer(client)
        target = Target(url="https://auth.example.com/")
        findings = await analyzer.analyze(target)
        redirect = [f for f in findings if "open-redirect" in f.tags]
        assert len(redirect) == 1
        assert redirect[0].severity == Severity.CRITICAL


# =====================================================================
# 3. XXE Checker Tests
# =====================================================================

class TestXxeChecker:
    """Tests for XxeChecker."""

    def _make_checker(self, client: FakeHttpClient):
        from krumpa.grotassault.xxe_payloads import XxeChecker
        c = XxeChecker(http_client=client)
        return c

    @pytest.mark.asyncio
    async def test_file_content_leaked(self):
        """Detect /etc/passwd content in response."""
        client = FakeHttpClient([
            FakeResponse(200, "root:x:0:0:root:/root:/bin/bash\n"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        file_findings = [f for f in findings if "file-read" in f.tags]
        assert len(file_findings) >= 1
        assert file_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_entity_expansion_detected(self):
        """Detect entity expansion in response."""
        expanded = "lol" * 100
        client = FakeHttpClient([
            FakeResponse(200, expanded),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        expansion = [f for f in findings if "entity-expansion" in f.tags]
        assert len(expansion) >= 1

    @pytest.mark.asyncio
    async def test_error_leak_detected(self):
        """Detect XML parser error messages."""
        error_body = "Error: org.xml.sax.SAXParseException: External entity not allowed"
        client = FakeHttpClient([
            FakeResponse(500, error_body),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        leaks = [f for f in findings if "info-leak" in f.tags]
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    async def test_safe_response_no_findings(self):
        """No findings when responses are safe."""
        client = FakeHttpClient([
            FakeResponse(400, "Bad request"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_get_without_xml_content_type_skipped(self):
        """GET requests without XML content-type should be skipped."""
        client = FakeHttpClient()
        checker = self._make_checker(client)
        target = Target(url="https://example.com/data", method="GET")
        findings = await checker.check(target)
        assert len(findings) == 0
        assert len(client.requests) == 0

    @pytest.mark.asyncio
    async def test_win_ini_detected(self):
        """Detect Windows win.ini content."""
        win_ini = "[fonts]\n[extensions]\n"
        client = FakeHttpClient([
            FakeResponse(200, win_ini),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/upload",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        file_findings = [f for f in findings if "file-read" in f.tags]
        assert len(file_findings) >= 1

    @pytest.mark.asyncio
    async def test_xml_content_type_get_tested(self):
        """GET with XML content-type SHOULD be tested."""
        client = FakeHttpClient([
            FakeResponse(400, "Bad request"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api",
            method="GET",
            headers={"Content-Type": "application/xml"},
        )
        findings = await checker.check(target)
        # Should have at least attempted to send payloads
        assert len(client.requests) > 0


class TestXxePayloadDatabase:
    """Test the payload databases are non-empty and valid XML-ish."""

    def test_all_payloads_non_empty(self):
        from krumpa.grotassault.xxe_payloads import ALL_XXE_PAYLOADS
        assert len(ALL_XXE_PAYLOADS) > 0

    def test_all_payloads_contain_xml_markers(self):
        from krumpa.grotassault.xxe_payloads import ALL_XXE_PAYLOADS
        for payload in ALL_XXE_PAYLOADS:
            assert "<?xml" in payload or "<!DOCTYPE" in payload or "<!ENTITY" in payload

    def test_payload_categories_distinct(self):
        from krumpa.grotassault.xxe_payloads import (
            _ENTITY_EXPANSION_PAYLOADS,
            _EXTERNAL_ENTITY_PAYLOADS,
            _PARAM_ENTITY_PAYLOADS,
            _BLIND_XXE_PAYLOADS,
        )
        all_payloads = (
            _ENTITY_EXPANSION_PAYLOADS
            + _EXTERNAL_ENTITY_PAYLOADS
            + _PARAM_ENTITY_PAYLOADS
            + _BLIND_XXE_PAYLOADS
        )
        assert len(all_payloads) == len(set(all_payloads))


# =====================================================================
# 4. SSRF Checker Tests
# =====================================================================

class TestSsrfChecker:
    """Tests for SsrfChecker."""

    def _make_checker(self, client: FakeHttpClient):
        from krumpa.grotassault.ssrf_payloads import SsrfChecker
        c = SsrfChecker(http_client=client)
        return c

    @pytest.mark.asyncio
    async def test_cloud_metadata_leaked(self):
        """Detect AWS metadata in response."""
        aws_response = '{"ami-id": "ami-12345", "instance-id": "i-abcde"}'
        client = FakeHttpClient([
            FakeResponse(200, aws_response),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/fetch?url=https://safe.com",
            method="GET",
        )
        findings = await checker.check(target, url_params=["url"])
        cloud = [f for f in findings if "cloud-metadata" in f.tags]
        assert len(cloud) >= 1
        assert cloud[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_local_file_detected(self):
        """Detect local file content via SSRF."""
        client = FakeHttpClient([
            FakeResponse(200, "root:x:0:0:root:/root:/bin/bash"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/proxy?url=https://safe.com",
            method="GET",
        )
        findings = await checker.check(target, url_params=["url"])
        file_findings = [f for f in findings if "file-read" in f.tags]
        assert len(file_findings) >= 1

    @pytest.mark.asyncio
    async def test_internal_service_reached(self):
        """Detect internal service indicators."""
        client = FakeHttpClient([
            FakeResponse(200, "redis_version:6.2.6\nconnected_clients:1"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/fetch?url=https://safe.com",
            method="GET",
        )
        findings = await checker.check(target, url_params=["url"])
        internal = [f for f in findings if "internal-access" in f.tags]
        assert len(internal) >= 1

    @pytest.mark.asyncio
    async def test_safe_response_no_findings(self):
        """No findings when responses don't indicate SSRF."""
        client = FakeHttpClient([
            FakeResponse(200, "Normal response body"),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/fetch?url=https://safe.com",
            method="GET",
        )
        findings = await checker.check(target, url_params=["url"])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_url_params_no_findings(self):
        """No findings when no URL-type parameters detected."""
        client = FakeHttpClient()
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/data",
            method="GET",
        )
        findings = await checker.check(target)
        assert len(findings) == 0
        assert len(client.requests) == 0

    @pytest.mark.asyncio
    async def test_auto_detect_url_params(self):
        """Should auto-detect URL-type parameter names from query string."""
        from krumpa.grotassault.ssrf_payloads import SsrfChecker
        target = Target(
            url="https://example.com/proxy?callback=https://safe.com&name=test",
            method="GET",
        )
        params = SsrfChecker._detect_url_params(target)
        assert "callback" in params
        assert "name" not in params

    @pytest.mark.asyncio
    async def test_body_url_params_detected(self):
        """Should detect URL params in JSON body."""
        from krumpa.grotassault.ssrf_payloads import SsrfChecker
        target = Target(
            url="https://example.com/api",
            method="POST",
            body='{"redirect": "https://safe.com", "name": "test"}',
        )
        params = SsrfChecker._detect_url_params(target)
        assert "redirect" in params

    @pytest.mark.asyncio
    async def test_post_body_injection(self):
        """SSRF payloads injected into POST body parameter."""
        aws_response = '{"security-credentials": "leaked"}'
        client = FakeHttpClient([
            FakeResponse(200, aws_response),
        ])
        checker = self._make_checker(client)
        target = Target(
            url="https://example.com/api/webhook",
            method="POST",
            body='{"url": "https://safe.com/hook"}',
        )
        findings = await checker.check(target, url_params=["url"])
        assert len(findings) >= 1


class TestSsrfPayloadDatabase:
    """Test the SSRF payload databases."""

    def test_all_payloads_non_empty(self):
        from krumpa.grotassault.ssrf_payloads import ALL_SSRF_PAYLOADS
        assert len(ALL_SSRF_PAYLOADS) > 0

    def test_cloud_metadata_payloads_contain_metadata_ip(self):
        from krumpa.grotassault.ssrf_payloads import _CLOUD_METADATA_PAYLOADS
        for payload in _CLOUD_METADATA_PAYLOADS:
            assert "169.254" in payload or "metadata" in payload.lower()

    def test_bypass_payloads_target_localhost(self):
        from krumpa.grotassault.ssrf_payloads import _BYPASS_PAYLOADS
        assert len(_BYPASS_PAYLOADS) >= 5


# =====================================================================
# 5. BOLA Generator Tests
# =====================================================================

class TestBolaGenerator:
    """Tests for BolaGenerator."""

    def _make_generator(self, **kwargs):
        from krumpa.openkrump.bola_generator import BolaGenerator
        return BolaGenerator(**kwargs)

    def _make_endpoint(self, path="/users/{id}", method="GET", params=None, security=None):
        from krumpa.openkrump.parser import ParsedEndpoint
        if params is None:
            params = [{"name": "id", "in": "path", "schema": {"type": "integer"}}]
        return ParsedEndpoint(
            path=path,
            method=method,
            parameters=params,
            security=security or [],
        )

    def test_generates_test_cases_for_id_param(self):
        gen = self._make_generator()
        ep = self._make_endpoint()
        cases = gen.generate([ep])
        assert len(cases) > 0
        assert all(c.param_name == "id" for c in cases)

    def test_no_cases_for_non_id_params(self):
        gen = self._make_generator()
        ep = self._make_endpoint(
            path="/users",
            params=[{"name": "format", "in": "query", "schema": {"type": "string"}}],
        )
        cases = gen.generate([ep])
        assert len(cases) == 0

    def test_uuid_param_detected(self):
        gen = self._make_generator()
        ep = self._make_endpoint(
            path="/orders/{orderId}",
            params=[{"name": "orderId", "in": "path", "schema": {"type": "string", "format": "uuid"}}],
        )
        cases = gen.generate([ep])
        assert len(cases) > 0
        # Should use UUID test values
        assert any("00000000" in c.test_value for c in cases)

    def test_integer_param_detected(self):
        gen = self._make_generator()
        ep = self._make_endpoint()
        cases = gen.generate([ep])
        assert any(c.test_value in ("2", "99999", "0", "-1") for c in cases)

    def test_multiple_endpoints(self):
        gen = self._make_generator()
        eps = [
            self._make_endpoint("/users/{id}", "GET"),
            self._make_endpoint("/orders/{orderId}", "GET", params=[
                {"name": "orderId", "in": "path", "schema": {"type": "integer"}},
            ]),
        ]
        cases = gen.generate(eps)
        paths = {c.url_template for c in cases}
        assert "/users/{id}" in paths
        assert "/orders/{orderId}" in paths

    def test_analyse_endpoints_flags_unsecured(self):
        gen = self._make_generator()
        ep = self._make_endpoint(security=[])
        findings = gen.analyse_endpoints([ep])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "bola" in findings[0].tags

    def test_analyse_endpoints_lower_severity_with_security(self):
        gen = self._make_generator()
        ep = self._make_endpoint(security=[{"bearerAuth": []}])
        findings = gen.analyse_endpoints([ep])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    def test_implicit_path_params_detected(self):
        """Parameters in path template but not in explicit params list."""
        gen = self._make_generator()
        from krumpa.openkrump.parser import ParsedEndpoint
        ep = ParsedEndpoint(
            path="/teams/{teamId}/members/{userId}",
            method="GET",
            parameters=[],  # no explicit param definitions
        )
        id_params = gen._find_id_params(ep)
        param_names = [name for name, _ in id_params]
        assert "userId" in param_names

    def test_custom_alternate_ids(self):
        gen = self._make_generator(alternate_ids={"integer": ["42", "1337"]})
        ep = self._make_endpoint()
        cases = gen.generate([ep])
        test_values = {c.test_value for c in cases}
        assert "42" in test_values
        assert "1337" in test_values

    def test_deduplication_in_analyse(self):
        """Same endpoint should only produce one finding."""
        gen = self._make_generator()
        ep = self._make_endpoint()
        findings = gen.analyse_endpoints([ep, ep])
        assert len(findings) == 1

    def test_is_id_param_patterns(self):
        from krumpa.openkrump.bola_generator import BolaGenerator
        assert BolaGenerator._is_id_param("id")
        assert BolaGenerator._is_id_param("userId")
        assert BolaGenerator._is_id_param("user_id")
        assert BolaGenerator._is_id_param("uuid")
        assert BolaGenerator._is_id_param("slug")
        assert not BolaGenerator._is_id_param("format")
        assert not BolaGenerator._is_id_param("page")
        assert not BolaGenerator._is_id_param("limit")


# =====================================================================
# 6. Baseline Comparison Tests
# =====================================================================

class TestBaseline:
    """Tests for Baseline save/load/compare."""

    def _make_baseline(self, path=None):
        from krumpa.waaaghgate.baseline import Baseline
        return Baseline(path=path)

    def _make_finding(self, title="Test finding", severity=Severity.MEDIUM, url="https://example.com"):
        return Finding(
            title=title,
            severity=severity,
            target=Target(url=url),
            cwe=79,
            tags=["test"],
        )

    def test_fingerprint_stable(self):
        """Same finding should produce same fingerprint."""
        bl = self._make_baseline()
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert bl.fingerprint(f1) == bl.fingerprint(f2)

    def test_fingerprint_varies_by_title(self):
        bl = self._make_baseline()
        f1 = self._make_finding(title="Finding A")
        f2 = self._make_finding(title="Finding B")
        assert bl.fingerprint(f1) != bl.fingerprint(f2)

    def test_fingerprint_varies_by_severity(self):
        bl = self._make_baseline()
        f1 = self._make_finding(severity=Severity.HIGH)
        f2 = self._make_finding(severity=Severity.LOW)
        assert bl.fingerprint(f1) != bl.fingerprint(f2)

    def test_fingerprint_varies_by_url(self):
        bl = self._make_baseline()
        f1 = self._make_finding(url="https://a.com")
        f2 = self._make_finding(url="https://b.com")
        assert bl.fingerprint(f1) != bl.fingerprint(f2)

    def test_build_and_count(self):
        bl = self._make_baseline()
        findings = [self._make_finding(title=f"Finding {i}") for i in range(5)]
        bl.build(findings)
        assert bl.count == 5

    def test_save_and_load_json(self):
        bl = self._make_baseline()
        findings = [
            self._make_finding(title="XSS in login"),
            self._make_finding(title="SQL injection", severity=Severity.HIGH),
        ]
        bl.build(findings)
        json_str = bl.save()

        bl2 = self._make_baseline()
        bl2.load(json_str=json_str)
        assert bl2.count == 2

    def test_save_and_load_file(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        bl = self._make_baseline(path=path)
        findings = [self._make_finding(title="Test XSS")]
        bl.build(findings)
        bl.save()

        bl2 = self._make_baseline()
        bl2.load(path=path)
        assert bl2.count == 1

    def test_compare_no_changes(self):
        bl = self._make_baseline()
        findings = [self._make_finding(title="Persistent finding")]
        bl.build(findings)
        diff = bl.compare(findings)
        assert len(diff.new_findings) == 0
        assert len(diff.fixed_findings) == 0
        assert len(diff.unchanged_findings) == 1
        assert not diff.has_regressions
        assert not diff.has_fixes

    def test_compare_new_finding(self):
        bl = self._make_baseline()
        old_findings = [self._make_finding(title="Old finding")]
        bl.build(old_findings)

        current = old_findings + [self._make_finding(title="New finding")]
        diff = bl.compare(current)
        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].title == "New finding"
        assert diff.has_regressions

    def test_compare_fixed_finding(self):
        bl = self._make_baseline()
        old_findings = [
            self._make_finding(title="Will be fixed"),
            self._make_finding(title="Stays"),
        ]
        bl.build(old_findings)

        current = [self._make_finding(title="Stays")]
        diff = bl.compare(current)
        assert len(diff.fixed_findings) == 1
        assert diff.fixed_findings[0]["title"] == "Will be fixed"
        assert diff.has_fixes

    def test_compare_mixed_changes(self):
        bl = self._make_baseline()
        old = [
            self._make_finding(title="A"),
            self._make_finding(title="B"),
            self._make_finding(title="C"),
        ]
        bl.build(old)

        current = [
            self._make_finding(title="B"),  # unchanged
            self._make_finding(title="D"),  # new
        ]
        diff = bl.compare(current)
        assert len(diff.unchanged_findings) == 1
        assert len(diff.new_findings) == 1
        assert len(diff.fixed_findings) == 2  # A and C fixed
        assert diff.baseline_count == 3
        assert diff.current_count == 2

    def test_summary_string(self):
        bl = self._make_baseline()
        bl.build([self._make_finding()])
        diff = bl.compare([self._make_finding()])
        summary = diff.summary()
        assert "Baseline: 1" in summary
        assert "Current: 1" in summary

    def test_load_missing_file_graceful(self, tmp_path):
        bl = self._make_baseline()
        bl.load(path=str(tmp_path / "nonexistent.json"))
        assert bl.count == 0

    def test_json_format_version(self):
        bl = self._make_baseline()
        bl.build([self._make_finding()])
        json_str = bl.save()
        data = json.loads(json_str)
        assert data["version"] == 1
        assert "created_at" in data
        assert data["count"] == 1
        assert len(data["findings"]) == 1

    def test_baseline_entry_roundtrip(self):
        from krumpa.waaaghgate.baseline import BaselineEntry
        entry = BaselineEntry(
            fingerprint="abc123",
            title="Test",
            severity="high",
            target_url="https://example.com",
            module="BossKey",
            cwe=79,
            tags=["xss"],
            first_seen="2024-01-01T00:00:00",
        )
        d = entry.to_dict()
        entry2 = BaselineEntry.from_dict(d)
        assert entry2.fingerprint == entry.fingerprint
        assert entry2.title == entry.title
        assert entry2.severity == entry.severity
        assert entry2.cwe == entry.cwe


# =====================================================================
# 7. Module integration tests
# =====================================================================

class TestBossKeyModuleIntegration:
    """Test CSRF + OAuth2 are wired into BossKeyModule."""

    def test_module_has_csrf_checker(self):
        from krumpa.bosskey.module import BossKeyModule
        mod = BossKeyModule()
        assert hasattr(mod, '_csrf_checker')

    def test_module_has_oauth2_analyzer(self):
        from krumpa.bosskey.module import BossKeyModule
        mod = BossKeyModule()
        assert hasattr(mod, '_oauth2_analyzer')

    @pytest.mark.asyncio
    async def test_setup_wires_clients(self):
        from krumpa.bosskey.module import BossKeyModule
        mod = BossKeyModule()
        ctx = ScanContext()
        ctx.http_client = FakeHttpClient()
        await mod.setup(ctx)
        assert mod._csrf_checker._client is ctx.http_client
        assert mod._oauth2_analyzer._client is ctx.http_client


class TestGrotAssaultModuleIntegration:
    """Test XXE + SSRF are wired into GrotAssaultModule."""

    def test_module_has_xxe_checker(self):
        from krumpa.grotassault.module import GrotAssaultModule
        mod = GrotAssaultModule()
        assert hasattr(mod, '_xxe_checker')

    def test_module_has_ssrf_checker(self):
        from krumpa.grotassault.module import GrotAssaultModule
        mod = GrotAssaultModule()
        assert hasattr(mod, '_ssrf_checker')

    @pytest.mark.asyncio
    async def test_setup_wires_clients(self):
        from krumpa.grotassault.module import GrotAssaultModule
        mod = GrotAssaultModule()
        ctx = ScanContext()
        ctx.http_client = FakeHttpClient()
        await mod.setup(ctx)
        assert mod._xxe_checker._client is ctx.http_client
        assert mod._ssrf_checker._client is ctx.http_client


class TestOpenKrumpModuleIntegration:
    """Test BOLA is wired into OpenKrumpModule."""

    def test_module_has_bola_generator(self):
        from krumpa.openkrump.module import OpenKrumpModule
        mod = OpenKrumpModule()
        assert hasattr(mod, '_bola_generator')


class TestImportsWork:
    """Verify all new exports are importable."""

    def test_bosskey_imports(self):
        from krumpa.bosskey import CsrfChecker, OAuth2Analyzer
        assert CsrfChecker is not None
        assert OAuth2Analyzer is not None

    def test_grotassault_imports(self):
        from krumpa.grotassault import XxeChecker, SsrfChecker, ALL_XXE_PAYLOADS, ALL_SSRF_PAYLOADS
        assert XxeChecker is not None
        assert SsrfChecker is not None
        assert len(ALL_XXE_PAYLOADS) > 0
        assert len(ALL_SSRF_PAYLOADS) > 0

    def test_openkrump_imports(self):
        from krumpa.openkrump import BolaGenerator, BolaTestCase
        assert BolaGenerator is not None
        assert BolaTestCase is not None

    def test_waaaghgate_imports(self):
        from krumpa.waaaghgate import Baseline, BaselineDiff
        assert Baseline is not None
        assert BaselineDiff is not None
