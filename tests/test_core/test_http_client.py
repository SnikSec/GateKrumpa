"""Tests for HttpClient — URL validation, SSRF protection, sanitisation, proxy chaining."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

from krumpa.core.http_client import (
    HttpClient,
    _sanitise_url,
    _SENSITIVE_PARAMS,
    _SUPPORTED_PROXY_SCHEMES,
)


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


# ------------------------------------------------------------------
# Proxy chaining / _resolve_proxy
# ------------------------------------------------------------------

class TestResolveProxy:
    """Unit tests for HttpClient._resolve_proxy static method."""

    def test_no_proxy_returns_none(self):
        assert HttpClient._resolve_proxy(None, None) is None

    def test_single_proxy_http(self):
        result = HttpClient._resolve_proxy("http://proxy:8080", None)
        assert result == "http://proxy:8080"

    def test_single_proxy_socks5(self):
        result = HttpClient._resolve_proxy("socks5://tor:9050", None)
        assert result == "socks5://tor:9050"

    def test_single_proxy_socks5h(self):
        result = HttpClient._resolve_proxy("socks5h://tor:9050", None)
        assert result == "socks5h://tor:9050"

    def test_single_proxy_socks4(self):
        result = HttpClient._resolve_proxy("socks4://old:1080", None)
        assert result == "socks4://old:1080"

    def test_chain_returns_last_entry(self):
        chain = ["socks5://hop1:9050", "http://hop2:8080", "http://exit:3128"]
        result = HttpClient._resolve_proxy(None, chain)
        assert result == "http://exit:3128"

    def test_chain_single_entry(self):
        result = HttpClient._resolve_proxy(None, ["https://only:443"])
        assert result == "https://only:443"

    def test_chain_overrides_proxy_param(self):
        """proxy_chain takes priority over proxy when both given."""
        result = HttpClient._resolve_proxy(
            "http://ignored:8080",
            ["socks5://hop1:9050", "http://used:3128"],
        )
        assert result == "http://used:3128"

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="Unsupported proxy scheme"):
            HttpClient._resolve_proxy("ftp://bad:21", None)

    def test_invalid_scheme_in_chain_raises(self):
        with pytest.raises(ValueError, match="Unsupported proxy scheme"):
            HttpClient._resolve_proxy(None, ["http://ok:8080", "ftp://bad:21"])

    def test_empty_chain_returns_none(self):
        assert HttpClient._resolve_proxy(None, []) is None

    def test_supported_schemes_constant(self):
        expected = {"http", "https", "socks5", "socks5h", "socks4"}
        assert _SUPPORTED_PROXY_SCHEMES == expected


class TestProxyChainProperty:
    """Tests for the active_proxy_chain property on constructed clients."""

    def test_no_proxy_empty_chain(self):
        c = HttpClient()
        assert c.active_proxy_chain == []

    def test_single_proxy_chain_property(self):
        c = HttpClient(proxy="http://proxy:8080")
        assert c.active_proxy_chain == ["http://proxy:8080"]

    def test_multi_hop_chain_property(self):
        chain = ["socks5://hop1:9050", "http://hop2:3128"]
        c = HttpClient(proxy_chain=chain)
        assert c.active_proxy_chain == chain

    def test_chain_property_returns_copy(self):
        c = HttpClient(proxy="http://proxy:8080")
        chain = c.active_proxy_chain
        chain.append("http://extra:9999")
        assert c.active_proxy_chain == ["http://proxy:8080"]
