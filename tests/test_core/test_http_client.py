"""Tests for HttpClient — URL validation, SSRF protection, sanitisation."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

from krumpa.core.http_client import HttpClient, _sanitise_url, _SENSITIVE_PARAMS


# ------------------------------------------------------------------
# URL validation / SSRF protection (no real network)
# ------------------------------------------------------------------

class TestValidateUrl:

    def _client(self, *, allow_private: bool = False) -> HttpClient:
        return HttpClient(allow_private_networks=allow_private)

    def test_blocks_localhost_ip(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://127.0.0.1/admin")

    def test_blocks_rfc1918_10(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://10.0.0.1/internal")

    def test_blocks_rfc1918_172(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://172.16.0.1/api")

    def test_blocks_rfc1918_192(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://192.168.1.1/api")

    def test_blocks_link_local(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_ipv6_loopback(self):
        c = self._client()
        with pytest.raises(ValueError, match="private/reserved"):
            c._validate_url("http://[::1]/api")

    def test_allows_public_ip(self):
        c = self._client()
        c._validate_url("https://93.184.216.34/page")  # should not raise

    def test_allows_hostnames(self):
        c = self._client()
        c._validate_url("https://example.com/api")  # DNS name, not blocked

    def test_allow_private_override(self):
        c = self._client(allow_private=True)
        c._validate_url("http://127.0.0.1/admin")  # should not raise

    def test_rejects_unsupported_scheme(self):
        c = self._client()
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            c._validate_url("ftp://example.com/file")

    def test_rejects_file_scheme(self):
        c = self._client()
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            c._validate_url("file:///etc/passwd")

    def test_rejects_empty_host(self):
        c = self._client()
        with pytest.raises(ValueError, match="Cannot determine host"):
            c._validate_url("http:///no-host")


# ------------------------------------------------------------------
# URL sanitisation (for safe logging)
# ------------------------------------------------------------------

class TestSanitiseUrl:

    def test_no_query_unchanged(self):
        url = "https://api.example.com/v1/users"
        assert _sanitise_url(url) == url

    def test_non_sensitive_params_unchanged(self):
        url = "https://api.com/search?q=test&page=1"
        assert _sanitise_url(url) == url

    def test_redacts_api_key(self):
        sanitised = _sanitise_url("https://api.com/data?api_key=SECRET123&page=1")
        assert "SECRET123" not in sanitised
        assert "api_key=***" in sanitised
        assert "page=1" in sanitised

    def test_redacts_token(self):
        sanitised = _sanitise_url("https://api.com/?token=abc123")
        assert "abc123" not in sanitised
        assert "token=***" in sanitised

    def test_redacts_password(self):
        sanitised = _sanitise_url("https://api.com/?password=hunter2")
        assert "hunter2" not in sanitised
        assert "password=***" in sanitised

    def test_redacts_multiple_sensitive(self):
        sanitised = _sanitise_url("https://api.com/?api_key=k1&secret=s2&q=ok")
        assert "k1" not in sanitised
        assert "s2" not in sanitised
        assert "q=ok" in sanitised

    def test_case_insensitive_redaction(self):
        sanitised = _sanitise_url("https://api.com/?API_KEY=test")
        assert "test" not in sanitised

    def test_all_sensitive_params_known(self):
        expected = {"api_key", "apikey", "token", "access_token", "password",
                    "secret", "key", "auth", "bearer", "session"}
        assert _SENSITIVE_PARAMS == expected


# ------------------------------------------------------------------
# Client construction and context manager
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestClientLifecycle:

    async def test_context_manager(self):
        async with HttpClient() as client:
            assert client is not None
        # should not raise after close

    async def test_close_is_idempotent(self):
        client = HttpClient()
        await client.close()
        # second close should not raise
        await client.close()


# ------------------------------------------------------------------
# Constructor options
# ------------------------------------------------------------------

class TestConstructorOptions:

    def test_default_values(self):
        c = HttpClient()
        assert c._rate_limit == 0.0
        assert c._allow_private_networks is False

    def test_custom_rate_limit(self):
        c = HttpClient(rate_limit=0.5)
        assert c._rate_limit == 0.5

    def test_verify_ssl_false_does_not_crash(self):
        # Just ensure construction succeeds with verify_ssl=False
        c = HttpClient(verify_ssl=False)
        assert c is not None
