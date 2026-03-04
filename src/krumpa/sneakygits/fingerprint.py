"""
SneakyGits — technology fingerprinting engine.

Identifies server-side and client-side technologies by inspecting:
  - HTTP response headers (``Server``, ``X-Powered-By``, ``X-Generator``, etc.)
  - HTML meta tags and generator hints
  - Known JavaScript library patterns
  - Cookie naming conventions
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import httpx

from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.fingerprint")


# ------------------------------------------------------------------
# Signature definitions
# ------------------------------------------------------------------

@dataclass(frozen=True)
class _Signature(HttpClientMixin):
    """A single fingerprint rule."""
    name: str
    category: str  # e.g. "server", "framework", "cms", "js-lib", "cdn"
    # At least one of the following must match for identification
    header_patterns: Dict[str, re.Pattern] = field(default_factory=dict)   # header-name → regex
    body_patterns: List[re.Pattern] = field(default_factory=list)
    cookie_patterns: List[re.Pattern] = field(default_factory=list)


def _h(pattern: str) -> re.Pattern:
    """Compile a case-insensitive header/body pattern."""
    return re.compile(pattern, re.IGNORECASE)


# Curated signature database — easily extensible
_SIGNATURES: List[_Signature] = [
    # ---- Servers ----
    _Signature(
        name="Nginx",
        category="server",
        header_patterns={"server": _h(r"nginx")},
    ),
    _Signature(
        name="Apache",
        category="server",
        header_patterns={"server": _h(r"apache")},
    ),
    _Signature(
        name="Microsoft-IIS",
        category="server",
        header_patterns={"server": _h(r"microsoft-iis")},
    ),
    _Signature(
        name="Cloudflare",
        category="cdn",
        header_patterns={"server": _h(r"cloudflare")},
        cookie_patterns=[_h(r"__cfduid|cf_clearance")],
    ),

    # ---- Frameworks / Runtimes ----
    _Signature(
        name="PHP",
        category="framework",
        header_patterns={"x-powered-by": _h(r"php")},
        cookie_patterns=[_h(r"PHPSESSID")],
    ),
    _Signature(
        name="ASP.NET",
        category="framework",
        header_patterns={"x-powered-by": _h(r"asp\.net"), "x-aspnet-version": _h(r".")},
        cookie_patterns=[_h(r"ASP\.NET_SessionId|\.ASPXAUTH")],
    ),
    _Signature(
        name="Express",
        category="framework",
        header_patterns={"x-powered-by": _h(r"express")},
    ),
    _Signature(
        name="Django",
        category="framework",
        header_patterns={"x-frame-options": _h(r"SAMEORIGIN")},
        cookie_patterns=[_h(r"csrftoken")],
        body_patterns=[_h(r"csrfmiddlewaretoken")],
    ),
    _Signature(
        name="Ruby on Rails",
        category="framework",
        header_patterns={"x-powered-by": _h(r"phusion passenger")},
        cookie_patterns=[_h(r"_rails_session|_session_id")],
        body_patterns=[_h(r'name="authenticity_token"')],
    ),

    # ---- CMS ----
    _Signature(
        name="WordPress",
        category="cms",
        body_patterns=[_h(r"wp-content/|wp-includes/"), _h(r'<meta name="generator" content="WordPress')],
    ),
    _Signature(
        name="Drupal",
        category="cms",
        header_patterns={"x-generator": _h(r"drupal")},
        body_patterns=[_h(r"Drupal\.settings|drupal\.js")],
    ),
    _Signature(
        name="Joomla",
        category="cms",
        body_patterns=[_h(r'<meta name="generator" content="Joomla'), _h(r"/media/jui/")],
    ),

    # ---- JS Libraries ----
    _Signature(
        name="jQuery",
        category="js-lib",
        body_patterns=[_h(r"jquery[\-.]?\d|jquery\.min\.js")],
    ),
    _Signature(
        name="React",
        category="js-lib",
        body_patterns=[_h(r"react\.production\.min\.js|_reactRootContainer|__NEXT_DATA__")],
    ),
    _Signature(
        name="Vue.js",
        category="js-lib",
        body_patterns=[_h(r"vue\.min\.js|vue\.runtime|v-cloak|data-v-")],
    ),
    _Signature(
        name="Angular",
        category="js-lib",
        body_patterns=[_h(r"ng-version=|angular\.min\.js|ng-app=")],
    ),

    # ---- Security headers (presence = useful info) ----
    _Signature(
        name="Strict-Transport-Security",
        category="security-header",
        header_patterns={"strict-transport-security": _h(r".")},
    ),
    _Signature(
        name="Content-Security-Policy",
        category="security-header",
        header_patterns={"content-security-policy": _h(r".")},
    ),
]


class Fingerprinter(HttpClientMixin):
    """
    Identify technologies running on a target by probing its HTTP responses.

    Parameters
    ----------
    http_client:
        Optional pre-configured :class:`HttpClient`.  A default one is
        created if omitted.
    extra_signatures:
        Additional :class:`_Signature` objects to append to the built-in set.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        extra_signatures: Optional[List[_Signature]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._signatures = list(_SIGNATURES)
        if extra_signatures:
            self._signatures.extend(extra_signatures)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def identify(self, url: str) -> List[str]:
        """
        Return a sorted list of technology names detected at *url*.
        """
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            resp = await self._fetch(client, url)
            if resp is None:
                return []

            matched: Set[str] = set()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text
            cookies = resp.headers.get("set-cookie", "")

            for sig in self._signatures:
                if self._matches(sig, headers, body, cookies):
                    matched.add(sig.name)
                    logger.debug("Matched %s (%s) on %s", sig.name, sig.category, url)

            logger.info("Fingerprinted %s — %d technologies", url, len(matched))
            return sorted(matched)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    async def _fetch(client: HttpClient, url: str):
        """Fetch *url*, returning the response or None on failure."""
        try:
            return await client.get(url)
        except (httpx.HTTPError, OSError):
            logger.debug("Fingerprint fetch failed for %s", url)
            return None

    @staticmethod
    def _matches(
        sig: _Signature,
        headers: Dict[str, str],
        body: str,
        cookies: str,
    ) -> bool:
        """Return True if any of *sig*'s patterns match."""
        for hdr_name, pattern in sig.header_patterns.items():
            value = headers.get(hdr_name, "")
            if value and pattern.search(value):
                return True

        for pattern in sig.body_patterns:
            if pattern.search(body):
                return True

        for pattern in sig.cookie_patterns:
            if pattern.search(cookies):
                return True

        return False
