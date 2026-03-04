"""
GateKrumpa core — HTTP transport layer.

Thin wrapper around ``httpx`` providing:
  - Rate-limiting
  - Retry logic
  - Request/response logging
  - Proxy support
  - Scope enforcement  (via :class:`ScopeManager`)
  - Auth injection      (via :class:`AuthProvider`)
  - Traffic recording   (via :class:`RequestRecorder`)
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from krumpa.core.auth import AuthProvider
from krumpa.core.recorder import RequestRecord, RequestRecorder
from krumpa.core.scope import ScopeManager

logger = logging.getLogger("krumpa.http")

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF = 1.0
_DEFAULT_MAX_REDIRECTS = 10

# Query parameter names whose values are redacted in debug logs
_SENSITIVE_PARAMS = frozenset({
    "api_key", "apikey", "token", "access_token", "password",
    "secret", "key", "auth", "bearer", "session",
})

# Private / reserved IPv4 networks that should be blocked by default
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class HttpClientMixin:
    """Mixin for components that accept an optional shared :class:`HttpClient`.

    Sub-components store the client in ``_client`` and a flag in
    ``_owns_client``.  Parent modules should call :meth:`set_client`
    rather than touching those protected attributes directly.
    """

    _client: Optional["HttpClient"]
    _owns_client: bool

    def set_client(self, client: "HttpClient", *, owns: bool = False) -> None:
        """Inject (or replace) the shared HTTP client on this component."""
        self._client = client
        self._owns_client = owns


class HttpClient:
    """Async HTTP client shared across modules."""

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        backoff: float = _DEFAULT_BACKOFF,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        rate_limit: float = 0.0,
        max_redirects: int = _DEFAULT_MAX_REDIRECTS,
        allow_private_networks: bool = False,
        scope: Optional[ScopeManager] = None,
        auth: Optional[AuthProvider] = None,
        recorder: Optional[RequestRecorder] = None,
    ) -> None:
        if not verify_ssl:
            logger.warning(
                "TLS certificate verification is DISABLED — "
                "connections are vulnerable to MitM attacks"
            )

        # Build SSL / verify parameter ----------------------------------
        # Priority: ca_bundle → verify_ssl bool
        ssl_verify: Any = verify_ssl
        if ca_bundle:
            import ssl as _ssl

            ssl_ctx = _ssl.create_default_context(cafile=ca_bundle)
            if client_cert:
                ssl_ctx.load_cert_chain(
                    certfile=client_cert,
                    keyfile=client_key,
                )
                logger.info("mTLS enabled — client cert: %s", client_cert)
            ssl_verify = ssl_ctx
        elif client_cert:
            import ssl as _ssl

            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.load_cert_chain(
                certfile=client_cert,
                keyfile=client_key,
            )
            logger.info("Client certificate loaded: %s", client_cert)
            ssl_verify = ssl_ctx

        transport_kwargs: Dict[str, Any] = {"retries": retries}
        if proxy:
            transport_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers or {},
            verify=ssl_verify,
            follow_redirects=True,
            max_redirects=max_redirects,
            transport=httpx.AsyncHTTPTransport(**transport_kwargs),
        )
        self._allow_private_networks = allow_private_networks
        self._backoff = backoff
        self._rate_limit = rate_limit
        self._last_request: float = 0.0
        self._scope = scope
        self._auth = auth
        self._recorder = recorder

    # -- public interface ---------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str | bytes] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Send a request with automatic retry, rate-limit, scope, auth, and recording."""
        # 1. Scope enforcement
        if self._scope and not self._scope.is_in_scope(url):
            raise ValueError(f"URL out of scope: {url}")

        # 2. Auth injection
        if self._auth:
            headers = self._auth.inject(headers)

        # 3. SSRF / URL validation
        self._validate_url(url)

        # 4. Rate limiting
        await self._throttle()

        logger.debug("%s %s", method, _sanitise_url(url))

        # 5. Send request (timed)
        start = asyncio.get_event_loop().time()
        resp = await self._client.request(
            method,
            url,
            headers=headers,
            content=body,
            json=json_body,
            params=params,
        )
        duration_ms = (asyncio.get_event_loop().time() - start) * 1000.0

        logger.debug("← %d %s (%d bytes)", resp.status_code, _sanitise_url(url), len(resp.content))

        # 6. Record traffic
        if self._recorder:
            preview_len = self._recorder.body_preview_length
            self._recorder.record(RequestRecord(
                method=method,
                url=url,
                status_code=resp.status_code,
                request_headers=dict(headers or {}),
                response_headers=dict(resp.headers),
                timestamp=datetime.now(timezone.utc),
                duration_ms=duration_ms,
                request_body=body if isinstance(body, str) else (body.decode("utf-8", errors="replace") if body else None),
                response_body_preview=resp.text[:preview_len] if resp.text else "",
            ))

        return resp

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw) -> httpx.Response:
        return await self.request("PUT", url, **kw)

    async def delete(self, url: str, **kw) -> httpx.Response:
        return await self.request("DELETE", url, **kw)

    async def close(self) -> None:
        await self._client.aclose()

    # -- internal -----------------------------------------------------------

    def _validate_url(self, url: str) -> None:
        """Block requests to private/reserved IP ranges unless explicitly allowed."""
        if self._allow_private_networks:
            return
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Cannot determine host from URL: {url}")
        try:
            addr = ipaddress.ip_address(hostname)
            for net in _BLOCKED_NETWORKS:
                if addr in net:
                    raise ValueError(
                        f"Request to private/reserved address {hostname} blocked "
                        f"(set allow_private_networks=True to override)"
                    )
        except ValueError as exc:
            if "blocked" in str(exc):
                raise
            # hostname is a DNS name — not a bare IP, that's fine

    async def _throttle(self) -> None:
        if self._rate_limit <= 0:
            return
        now = asyncio.get_event_loop().time()
        gap = now - self._last_request
        if gap < self._rate_limit:
            await asyncio.sleep(self._rate_limit - gap)
        self._last_request = asyncio.get_event_loop().time()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


def _sanitise_url(url: str) -> str:
    """Strip sensitive query-parameter values from a URL for safe logging."""
    parsed = urlparse(url)
    if not parsed.query:
        return url
    parts = parsed.query.split("&")
    clean: list[str] = []
    for part in parts:
        if "=" in part:
            key, _val = part.split("=", 1)
            if key.lower() in _SENSITIVE_PARAMS:
                clean.append(f"{key}=***")
            else:
                clean.append(part)
        else:
            clean.append(part)
    return parsed._replace(query="&".join(clean)).geturl()
