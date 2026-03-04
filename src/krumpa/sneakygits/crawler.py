"""
SneakyGits — link crawler for endpoint discovery.

Crawls a target URL up to a configurable depth, extracting links from:
  - HTML ``<a>``, ``<form>``, ``<script>``, ``<link>`` tags
  - ``robots.txt`` disallow / allow paths
  - XML sitemaps (``sitemap.xml``)
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.crawler")

# Regex patterns for extracting URLs from HTML
_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)
_ROBOTS_RULE_RE = re.compile(
    r"^(?:Dis)?Allow:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
_ROBOTS_SITEMAP_RE = re.compile(
    r"^Sitemap:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)

# Extensions to skip (binary / non-content resources)
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
})


class Crawler(HttpClientMixin):
    """
    Async link crawler that discovers endpoints reachable from a seed URL.

    Parameters
    ----------
    max_depth:
        Maximum link-follow depth from the seed URL.
    follow_redirects:
        Whether to follow HTTP 3xx redirects.
    same_origin_only:
        If True (default), only keep URLs sharing the seed's origin.
    http_client:
        Optional pre-configured :class:`HttpClient`. A default one is
        created if omitted.
    """

    def __init__(
        self,
        *,
        max_depth: int = 3,
        max_pages: int = 500,
        follow_redirects: bool = True,
        same_origin_only: bool = True,
        http_client: Optional[HttpClient] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.follow_redirects = follow_redirects
        self.same_origin_only = same_origin_only
        self._client = http_client
        self._owns_client = http_client is None
        self._captured_cookies: Dict[str, List[str]] = {}
        self._auth_headers: Dict[str, str] = auth_headers or {}
        self._auth_cookies: Dict[str, str] = auth_cookies or {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def captured_cookies(self) -> Dict[str, List[str]]:
        """Map of URL → list of raw ``Set-Cookie`` header values seen."""
        return dict(self._captured_cookies)

    def inject_auth(
        self,
        *,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        """Set authentication headers/cookies for crawling behind auth."""
        if headers:
            self._auth_headers.update(headers)
        if cookies:
            self._auth_cookies.update(cookies)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self, seed_url: str) -> List[str]:
        """
        Crawl from *seed_url* and return all discovered endpoint URLs.

        The seed itself is always included in the result set.
        """
        client = self._client or HttpClient(timeout=15.0, retries=2)
        try:
            visited: Set[str] = set()
            discovered: Set[str] = set()
            origin = self._origin(seed_url)

            # Kick off by checking robots.txt and sitemap first
            robots_urls = await self._parse_robots(client, seed_url)
            sitemap_urls = await self._parse_sitemap(client, seed_url)

            # Seed the queue with everything we found passively
            queue: List[_CrawlItem] = []
            for url in {seed_url} | robots_urls | sitemap_urls:
                if self._should_include(url, origin):
                    queue.append(_CrawlItem(url=url, depth=0))

            while queue:
                if len(discovered) >= self.max_pages:
                    logger.info(
                        "Crawl of %s hit max_pages limit (%d)",
                        seed_url, self.max_pages,
                    )
                    break

                item = queue.pop(0)
                normalised = self._normalise(item.url)
                if normalised in visited:
                    continue
                visited.add(normalised)
                discovered.add(normalised)

                if item.depth >= self.max_depth:
                    continue

                links = await self._extract_links(client, normalised)
                for link in links:
                    link_norm = self._normalise(link)
                    if link_norm not in visited and self._should_include(link_norm, origin):
                        queue.append(_CrawlItem(url=link_norm, depth=item.depth + 1))

            logger.info("Crawl of %s complete — %d URLs discovered", seed_url, len(discovered))
            return sorted(discovered)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    async def _extract_links(self, client: HttpClient, url: str) -> List[str]:
        """Fetch *url* and return all href/src links found in the response."""
        try:
            req_headers: Optional[Dict[str, str]] = None
            if self._auth_headers or self._auth_cookies:
                req_headers = dict(self._auth_headers)
                if self._auth_cookies:
                    cookie_str = "; ".join(
                        f"{k}={v}" for k, v in self._auth_cookies.items()
                    )
                    existing = req_headers.get("Cookie", "")
                    req_headers["Cookie"] = (
                        f"{existing}; {cookie_str}" if existing else cookie_str
                    )
            resp = await client.get(url, headers=req_headers)
        except (httpx.HTTPError, OSError):
            logger.debug("Failed to fetch %s — skipping", url)
            return []

        # Capture Set-Cookie headers for session data flow
        if hasattr(resp.headers, "get_list"):
            set_cookies = resp.headers.get_list("set-cookie")
        else:
            val = resp.headers.get("set-cookie")
            set_cookies = [val] if val else []
        if set_cookies:
            self._captured_cookies.setdefault(url, []).extend(set_cookies)

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type and "xml" not in content_type:
            return []

        text = resp.text
        raw_links = _HREF_RE.findall(text)
        resolved: List[str] = []
        for raw in raw_links:
            absolute = urljoin(url, raw)
            if not self._is_skippable(absolute):
                resolved.append(absolute)
        return resolved

    # ------------------------------------------------------------------
    # robots.txt
    # ------------------------------------------------------------------

    async def _parse_robots(self, client: HttpClient, seed_url: str) -> Set[str]:
        """Parse ``robots.txt`` for paths and sitemap references."""
        robots_url = urljoin(seed_url, "/robots.txt")
        urls: Set[str] = set()
        try:
            resp = await client.get(robots_url)
            if resp.status_code != 200:
                return urls
            text = resp.text

            for match in _ROBOTS_RULE_RE.finditer(text):
                path = match.group(1).strip()
                if path and path != "/":
                    urls.add(urljoin(seed_url, path))

            for match in _ROBOTS_SITEMAP_RE.finditer(text):
                sitemap_url = match.group(1).strip()
                sitemap_urls = await self._fetch_sitemap(client, sitemap_url)
                urls.update(sitemap_urls)

        except (httpx.HTTPError, OSError):
            logger.debug("Could not fetch robots.txt for %s", seed_url)
        return urls

    # ------------------------------------------------------------------
    # Sitemap
    # ------------------------------------------------------------------

    async def _parse_sitemap(self, client: HttpClient, seed_url: str) -> Set[str]:
        """Try the default ``/sitemap.xml`` location."""
        sitemap_url = urljoin(seed_url, "/sitemap.xml")
        return await self._fetch_sitemap(client, sitemap_url)

    async def _fetch_sitemap(
        self, client: HttpClient, url: str, *, _depth: int = 0, _seen: Optional[Set[str]] = None,
    ) -> Set[str]:
        """Download and parse a sitemap (or sitemap index) at *url*."""
        max_depth = 3
        if _seen is None:
            _seen = set()
        if _depth >= max_depth or url in _seen:
            return set()
        _seen.add(url)

        urls: Set[str] = set()
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return urls
            text = resp.text
            for match in _SITEMAP_LOC_RE.finditer(text):
                loc = match.group(1).strip()
                if loc.endswith(".xml"):
                    urls.update(await self._fetch_sitemap(
                        client, loc, _depth=_depth + 1, _seen=_seen,
                    ))
                else:
                    urls.add(loc)
        except (httpx.HTTPError, OSError):
            logger.debug("Could not fetch sitemap at %s", url)
        return urls

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_include(self, url: str, origin: str) -> bool:
        if self.same_origin_only and self._origin(url) != origin:
            return False
        return url.startswith(("http://", "https://"))

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _normalise(url: str) -> str:
        """Strip fragments and trailing slashes for deduplication."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        qs = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}{qs}"

    @staticmethod
    def _is_skippable(url: str) -> bool:
        parsed = urlparse(url)
        for ext in _SKIP_EXTENSIONS:
            if parsed.path.lower().endswith(ext):
                return True
        return False


# ------------------------------------------------------------------
# Internal data
# ------------------------------------------------------------------

class _CrawlItem(HttpClientMixin):
    """Lightweight queue item."""
    __slots__ = ("url", "depth")

    def __init__(self, url: str, depth: int) -> None:
        self.url = url
        self.depth = depth
