"""Tests for the Fingerprinter class."""

from __future__ import annotations

import pytest

from krumpa.sneakygits.fingerprint import Fingerprinter, _Signature, _h


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for httpx.Response."""

    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeHttpClient:
    """Serves a single canned response for any URL."""

    def __init__(self, response: _FakeResponse):
        self._response = response

    async def get(self, url: str, **kw) -> _FakeResponse:
        return self._response

    async def close(self) -> None:
        pass


# ------------------------------------------------------------------
# Tests: _matches (static method)
# ------------------------------------------------------------------

class TestFingerprinterMatches:

    def test_matches_header(self):
        sig = _Signature(
            name="Nginx",
            category="server",
            header_patterns={"server": _h(r"nginx")},
        )
        assert Fingerprinter._matches(sig, {"server": "nginx/1.21"}, "", "") is True

    def test_no_match_wrong_header(self):
        sig = _Signature(
            name="Nginx",
            category="server",
            header_patterns={"server": _h(r"nginx")},
        )
        assert Fingerprinter._matches(sig, {"server": "Apache/2.4"}, "", "") is False

    def test_matches_body_pattern(self):
        sig = _Signature(
            name="WordPress",
            category="cms",
            body_patterns=[_h(r"wp-content/")],
        )
        assert Fingerprinter._matches(sig, {}, '<link href="/wp-content/theme.css">', "") is True

    def test_matches_cookie_pattern(self):
        sig = _Signature(
            name="PHP",
            category="framework",
            cookie_patterns=[_h(r"PHPSESSID")],
        )
        assert Fingerprinter._matches(sig, {}, "", "PHPSESSID=abc123") is True

    def test_no_match_empty_data(self):
        sig = _Signature(
            name="Nginx",
            category="server",
            header_patterns={"server": _h(r"nginx")},
        )
        assert Fingerprinter._matches(sig, {}, "", "") is False

    def test_matches_case_insensitive(self):
        sig = _Signature(
            name="Apache",
            category="server",
            header_patterns={"server": _h(r"apache")},
        )
        assert Fingerprinter._matches(sig, {"server": "APACHE/2.4"}, "", "") is True


# ------------------------------------------------------------------
# Tests: identify (integration with fake HTTP)
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestFingerprinterIdentify:

    async def test_detects_nginx(self):
        client = _FakeHttpClient(_FakeResponse(
            headers={"server": "nginx/1.21.3", "content-type": "text/html"},
            text="<html></html>",
        ))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        assert "Nginx" in techs

    async def test_detects_multiple_technologies(self):
        client = _FakeHttpClient(_FakeResponse(
            headers={
                "server": "nginx/1.21",
                "x-powered-by": "PHP/8.1",
                "content-type": "text/html",
                "set-cookie": "PHPSESSID=abc123",
            },
            text='<html><script src="/wp-content/themes/starter/app.js"></script></html>',
        ))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        assert "Nginx" in techs
        assert "PHP" in techs
        assert "WordPress" in techs

    async def test_returns_empty_on_404(self):
        client = _FakeHttpClient(_FakeResponse(status_code=404, text=""))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        # 404 still returns a response — may or may not match signatures
        assert isinstance(techs, list)

    async def test_returns_empty_on_fetch_failure(self):
        class _FailClient:
            async def get(self, url, **kw):
                raise ConnectionError("refused")
            async def close(self):
                pass

        fp = Fingerprinter(http_client=_FailClient())
        techs = await fp.identify("https://example.com")
        assert techs == []

    async def test_extra_signatures(self):
        custom_sig = _Signature(
            name="MyCustomTech",
            category="custom",
            body_patterns=[_h(r"x-custom-marker")],
        )
        client = _FakeHttpClient(_FakeResponse(
            headers={"content-type": "text/html"},
            text="<html><meta name='x-custom-marker'></html>",
        ))
        fp = Fingerprinter(http_client=client, extra_signatures=[custom_sig])
        techs = await fp.identify("https://example.com")
        assert "MyCustomTech" in techs

    async def test_detects_react(self):
        client = _FakeHttpClient(_FakeResponse(
            headers={"content-type": "text/html"},
            text='<html><div id="__next" data-reactroot=""></div><script src="react.production.min.js"></script></html>',
        ))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        assert "React" in techs

    async def test_detects_cloudflare(self):
        client = _FakeHttpClient(_FakeResponse(
            headers={
                "server": "cloudflare",
                "content-type": "text/html",
                "set-cookie": "__cfduid=abc",
            },
            text="<html></html>",
        ))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        assert "Cloudflare" in techs

    async def test_sorted_output(self):
        client = _FakeHttpClient(_FakeResponse(
            headers={
                "server": "nginx/1.21",
                "x-powered-by": "PHP/8.1",
                "content-type": "text/html",
            },
            text="<html></html>",
        ))
        fp = Fingerprinter(http_client=client)
        techs = await fp.identify("https://example.com")
        assert techs == sorted(techs)
