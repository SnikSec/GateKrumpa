"""Tests for the Crawler class."""

from __future__ import annotations

import pytest

from krumpa.sneakygits.crawler import Crawler, _CrawlItem


# ------------------------------------------------------------------
# Unit: helpers
# ------------------------------------------------------------------

class TestCrawlerHelpers:
    """Pure-function tests that don't require HTTP."""

    def test_origin_extracts_scheme_and_netloc(self):
        assert Crawler._origin("https://example.com/path?q=1") == "https://example.com"

    def test_origin_preserves_port(self):
        assert Crawler._origin("http://localhost:8080/api") == "http://localhost:8080"

    def test_normalise_strips_fragment(self):
        assert Crawler._normalise("https://example.com/page#section") == "https://example.com/page"

    def test_normalise_strips_trailing_slash(self):
        assert Crawler._normalise("https://example.com/page/") == "https://example.com/page"

    def test_normalise_preserves_query_string(self):
        assert Crawler._normalise("https://example.com/search?q=test") == "https://example.com/search?q=test"

    def test_normalise_root_path(self):
        assert Crawler._normalise("https://example.com") == "https://example.com/"

    def test_is_skippable_image(self):
        assert Crawler._is_skippable("https://example.com/logo.png") is True
        assert Crawler._is_skippable("https://example.com/photo.JPEG") is True

    def test_is_skippable_html(self):
        assert Crawler._is_skippable("https://example.com/page.html") is False

    def test_is_skippable_no_extension(self):
        assert Crawler._is_skippable("https://example.com/api/users") is False

    def test_should_include_same_origin(self):
        crawler = Crawler(same_origin_only=True)
        origin = "https://example.com"
        assert crawler._should_include("https://example.com/page", origin) is True
        assert crawler._should_include("https://other.com/page", origin) is False

    def test_should_include_cross_origin(self):
        crawler = Crawler(same_origin_only=False)
        assert crawler._should_include("https://other.com/page", "https://example.com") is True

    def test_should_include_rejects_non_http(self):
        crawler = Crawler(same_origin_only=False)
        assert crawler._should_include("ftp://example.com/file", "https://example.com") is False
        assert crawler._should_include("javascript:void(0)", "https://example.com") is False


class TestCrawlItem:
    def test_slots(self):
        item = _CrawlItem(url="https://example.com", depth=2)
        assert item.url == "https://example.com"
        assert item.depth == 2


# ------------------------------------------------------------------
# Integration: crawl with mocked HTTP
# ------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/html"}


class _FakeHttpClient:
    """Fake HttpClient that serves canned responses keyed by URL."""

    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses

    async def get(self, url: str, **kw) -> _FakeResponse:
        return self._responses.get(url, _FakeResponse(status_code=404, text=""))

    async def close(self) -> None:
        pass


@pytest.mark.asyncio
class TestCrawlerCrawl:

    async def test_single_page_no_links(self):
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text="<html><body>Hello</body></html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=2, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert urls == ["https://example.com/"]

    async def test_discovers_linked_pages(self):
        index_html = """
        <html><body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </body></html>
        """
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text=index_html),
            "https://example.com/about": _FakeResponse(text="<html>About</html>"),
            "https://example.com/contact": _FakeResponse(text="<html>Contact</html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=2, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert "https://example.com/about" in urls
        assert "https://example.com/contact" in urls

    async def test_respects_max_depth(self):
        """With max_depth=0 only the seed is returned (no following)."""
        index_html = '<html><a href="/deep">Deep</a></html>'
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text=index_html),
            "https://example.com/deep": _FakeResponse(text="<html>Deep</html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=0, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert urls == ["https://example.com/"]

    async def test_skips_cross_origin(self):
        index_html = '<html><a href="https://evil.com/page">External</a></html>'
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text=index_html),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=2, same_origin_only=True, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert "https://evil.com/page" not in urls

    async def test_robots_txt_paths_added(self):
        robots = "User-agent: *\nDisallow: /admin\nAllow: /public\n"
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text="<html></html>"),
            "https://example.com/robots.txt": _FakeResponse(text=robots),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
            "https://example.com/admin": _FakeResponse(text="<html>Admin</html>"),
            "https://example.com/public": _FakeResponse(text="<html>Public</html>"),
        })
        crawler = Crawler(max_depth=1, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert "https://example.com/admin" in urls
        assert "https://example.com/public" in urls

    async def test_sitemap_urls_added(self):
        sitemap_xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/page1</loc></url>
            <url><loc>https://example.com/page2</loc></url>
        </urlset>
        """
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text="<html></html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(text=sitemap_xml, headers={"content-type": "application/xml"}),
            "https://example.com/page1": _FakeResponse(text="<html>Page1</html>"),
            "https://example.com/page2": _FakeResponse(text="<html>Page2</html>"),
        })
        crawler = Crawler(max_depth=1, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert "https://example.com/page1" in urls
        assert "https://example.com/page2" in urls

    async def test_deduplicates_urls(self):
        """Same link referenced multiple times should appear once."""
        index_html = """
        <html>
            <a href="/dup">Link 1</a>
            <a href="/dup">Link 2</a>
            <a href="/dup/">Link 3 with trailing slash</a>
        </html>
        """
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text=index_html),
            "https://example.com/dup": _FakeResponse(text="<html>Dup</html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=2, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert urls.count("https://example.com/dup") == 1

    async def test_skips_binary_extensions(self):
        index_html = '<html><a href="/image.png">Pic</a><a href="/page">Page</a></html>'
        client = _FakeHttpClient({
            "https://example.com/": _FakeResponse(text=index_html),
            "https://example.com/page": _FakeResponse(text="<html></html>"),
            "https://example.com/robots.txt": _FakeResponse(status_code=404),
            "https://example.com/sitemap.xml": _FakeResponse(status_code=404),
        })
        crawler = Crawler(max_depth=2, http_client=client)
        urls = await crawler.crawl("https://example.com/")
        assert "https://example.com/image.png" not in urls
        assert "https://example.com/page" in urls
