"""
SneakyGits — JavaScript endpoint extraction.

Parse JavaScript files for API routes, fetch URLs, XHR calls,
and hardcoded secrets.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.js_extractor")


# ------------------------------------------------------------------
# Extraction patterns
# ------------------------------------------------------------------

# API route / URL patterns in JavaScript source
_URL_PATTERNS: List[re.Pattern[str]] = [
    # Absolute URLs
    re.compile(r'''["'`](https?://[^\s"'`<>{}|\\^]+)["'`]''', re.IGNORECASE),
    # Relative API paths
    re.compile(r'''["'`](/api/[^\s"'`<>{}|\\^]+)["'`]''', re.IGNORECASE),
    re.compile(r'''["'`](/v[0-9]+/[^\s"'`<>{}|\\^]+)["'`]''', re.IGNORECASE),
    # fetch / axios / XMLHttpRequest calls
    re.compile(r'''fetch\s*\(\s*["'`]([^\s"'`]+)["'`]''', re.IGNORECASE),
    re.compile(r'''axios\.(?:get|post|put|patch|delete)\s*\(\s*["'`]([^\s"'`]+)["'`]''', re.IGNORECASE),
    re.compile(r'''\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^\s"'`]+)["'`]''', re.IGNORECASE),
    # Route definitions (React Router, Express, etc.)
    re.compile(r'''path\s*:\s*["'`](/[^\s"'`]+)["'`]'''),
    re.compile(r'''route\s*\(\s*["'`](/[^\s"'`]+)["'`]''', re.IGNORECASE),
]

# Secret / sensitive value patterns
_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {"name": "AWS Access Key", "pattern": re.compile(r"AKIA[0-9A-Z]{16}"), "severity": Severity.CRITICAL},
    {"name": "AWS Secret Key", "pattern": re.compile(r'''["'`][0-9a-zA-Z/+=]{40}["'`]'''), "severity": Severity.HIGH},
    {"name": "Generic API Key", "pattern": re.compile(r'''(?:api[_-]?key|apikey)\s*[:=]\s*["'`]([^"'`]{8,})["'`]''', re.IGNORECASE), "severity": Severity.HIGH},
    {"name": "Bearer Token", "pattern": re.compile(r'''["'`]Bearer\s+[A-Za-z0-9._~+/=-]+["'`]''', re.IGNORECASE), "severity": Severity.HIGH},
    {"name": "JWT", "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "severity": Severity.HIGH},
    {"name": "Private Key", "pattern": re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA)?\s*PRIVATE\s+KEY-----"), "severity": Severity.CRITICAL},
    {"name": "Google API Key", "pattern": re.compile(r"AIza[0-9A-Za-z_-]{35}"), "severity": Severity.HIGH},
    {"name": "Slack Token", "pattern": re.compile(r"xox[bpors]-[0-9A-Za-z-]+"), "severity": Severity.HIGH},
    {"name": "GitHub Token", "pattern": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "severity": Severity.HIGH},
    {"name": "Generic Secret", "pattern": re.compile(r'''(?:secret|password|passwd|token)\s*[:=]\s*["'`]([^"'`]{8,})["'`]''', re.IGNORECASE), "severity": Severity.MEDIUM},
]

# Source map detection
_SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


@dataclass
class JsExtractionResult(HttpClientMixin):
    """Aggregated results from JS analysis."""
    urls: Set[str] = field(default_factory=set)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    js_files_scanned: int = 0


class JsExtractor(HttpClientMixin):
    """
    Discover JavaScript files on a target, download them, and extract
    API endpoints, secrets, and source-map references.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def extract(self, target: Target) -> List[Finding]:
        """Scan the target for JS files and extract endpoints/secrets."""
        findings: List[Finding] = []
        result = JsExtractionResult()

        # Gather JS file URLs from the page or target metadata
        js_urls = await self._find_js_files(target)

        client = self._get_client()
        try:
            for js_url in js_urls:
                try:
                    resp = await client.request("GET", js_url)
                    source = getattr(resp, "text", "") or ""
                    if source:
                        result.js_files_scanned += 1
                        self._extract_from_source(source, js_url, target, result)
                except Exception as exc:
                    logger.debug("Failed to fetch JS %s: %s", js_url, exc)
        finally:
            self._maybe_close(client)

        # Convert results to findings
        if result.urls:
            all_urls = sorted(result.urls)
            findings.append(Finding(
                title=f"API endpoints extracted from JavaScript ({len(result.urls)})",
                description=(
                    f"Found {len(result.urls)} API endpoints in {result.js_files_scanned} "
                    f"JavaScript files on {target.url}"
                ),
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {u}" for u in all_urls[:50]),
                tags=["recon", "js-extraction", "api-endpoints"],
            ))

        for secret in result.secrets:
            findings.append(Finding(
                title=f"Secret in JavaScript: {secret['name']}",
                description=(
                    f"Found {secret['name']} in {secret.get('source', 'JavaScript')}. "
                    f"Client-side secrets can be extracted by any visitor."
                ),
                severity=Severity(secret.get("severity", "high")),
                target=target,
                evidence=f"Match: {secret.get('match', '')[:100]}",
                remediation="Move secrets to server-side environment variables. Never embed credentials in client-side JavaScript.",
                cwe=798,
                tags=["recon", "js-extraction", "secret", "credential"],
            ))

        if result.source_maps:
            findings.append(Finding(
                title=f"Source maps detected ({len(result.source_maps)})",
                description=(
                    f"JavaScript source maps found — these may expose original "
                    f"source code, comments, and internal variable names."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(f"  {sm}" for sm in result.source_maps),
                remediation="Remove source maps from production deployments.",
                cwe=540,
                tags=["recon", "js-extraction", "source-map"],
            ))

        return findings

    def extract_from_source(
        self, source: str, *, base_url: str = "",
    ) -> JsExtractionResult:
        """Extract endpoints and secrets from raw JS source (no HTTP)."""
        result = JsExtractionResult(js_files_scanned=1)
        target = Target(url=base_url or "https://example.com")
        self._extract_from_source(source, base_url, target, result)
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _find_js_files(self, target: Target) -> List[str]:
        """Fetch the page HTML and extract <script src="..."> URLs."""
        js_urls: List[str] = []

        # Check target metadata for pre-discovered JS
        meta_js = target.metadata.get("js_files", [])
        js_urls.extend(meta_js)

        client = self._get_client()
        try:
            resp = await client.request("GET", target.url)
            html = getattr(resp, "text", "") or ""
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = m.group(1)
                if src.endswith(".js") or ".js?" in src:
                    full_url = urljoin(target.url, src)
                    if full_url not in js_urls:
                        js_urls.append(full_url)
        except Exception as exc:
            logger.debug("Failed to fetch page for JS discovery: %s", exc)
        finally:
            self._maybe_close(client)

        return js_urls

    def _extract_from_source(
        self,
        source: str,
        js_url: str,
        target: Target,
        result: JsExtractionResult,
    ) -> None:
        """Parse a single JS file for URLs, secrets, and source maps."""
        base = target.url

        # URLs
        for pattern in _URL_PATTERNS:
            for m in pattern.finditer(source):
                url = m.group(1)
                if self._is_valid_url(url):
                    if url.startswith("/"):
                        url = urljoin(base, url)
                    result.urls.add(url)

        # Secrets
        for spec in _SECRET_PATTERNS:
            for m in spec["pattern"].finditer(source):
                match_text = m.group(0)
                result.secrets.append({
                    "name": spec["name"],
                    "severity": spec["severity"].value,
                    "match": match_text,
                    "source": js_url,
                })

        # Source maps
        for m in _SOURCEMAP_PATTERN.finditer(source):
            map_url = m.group(1)
            full_url = urljoin(js_url or base, map_url)
            result.source_maps.append(full_url)

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        """Filter out noise — data URIs, tiny fragments, etc."""
        if len(url) < 5:
            return False
        if url.startswith(("data:", "javascript:", "blob:", "mailto:", "#")):
            return False
        # Skip common static assets
        if re.search(r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot)(\?|$)', url, re.IGNORECASE):
            return False
        return True

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
