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

# JSON body field patterns — extract field names from fetch/axios POST payloads (DAST-H2)
# These capture keys inside object literals passed to fetch/axios body arguments.
_BODY_FIELD_PATTERNS: List[re.Pattern[str]] = [
    # JSON object keys: { "key": ..., "key2": ... }
    re.compile(r'''["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']\s*:'''),
    # GraphQL variables block
    re.compile(r'''variables\s*:\s*\{([^}]{1,300})\}'''),
    # FormData.append("fieldName", ...)
    re.compile(r'''\.append\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']'''),
]

# Directory listing response indicators (DAST-H1)
_DIRECTORY_LISTING_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"<title>Index of /", re.IGNORECASE),            # Nginx / Apache autoindex
    re.compile(r"<h1>Index of /", re.IGNORECASE),               # Apache
    re.compile(r"Directory listing for /", re.IGNORECASE),       # Python SimpleHTTPServer
    re.compile(r'href="[^"]+/">\.\./', re.IGNORECASE),           # Generic parent-dir link
    re.compile(r"<pre>.*\.\./.*</pre>", re.IGNORECASE | re.DOTALL),  # Apache directory listing body
    re.compile(r"Apache Tomcat.*directory listing", re.IGNORECASE),
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
    # DAST-H2: discovered JSON body parameter names for grotassault
    body_params: Set[str] = field(default_factory=set)


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

        # DAST-H2: store discovered body params in target metadata for grotassault
        if result.body_params:
            target.metadata.setdefault("js_discovered_params", []).extend(
                sorted(result.body_params)
            )

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

        # DAST-H1: emit directory listing finding if detected during page fetch
        if target.metadata.get("directory_listing_detected"):
            findings.append(Finding(
                title="Directory listing enabled",
                description=(
                    "The web server is configured to display a directory index when no "
                    "index file is present. This exposes the full file hierarchy to "
                    "unauthenticated visitors and may leak source code, backup files, "
                    "or configuration data."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Directory listing response detected at {target.url}",
                remediation=(
                    "Disable autoindex in Nginx (`autoindex off;`), Apache (`Options -Indexes`), "
                    "or Tomcat (`listings=false` in DefaultServlet config)."
                ),
                cwe=548,
                tags=["recon", "directory-listing", "information-exposure"],
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
        """Fetch the page HTML and extract <script src="..."> URLs.

        Also checks the page HTML for directory listing patterns (DAST-H1)
        and stores the result in ``target.metadata["directory_listing_detected"]``.
        """
        js_urls: List[str] = []

        # Check target metadata for pre-discovered JS
        meta_js = target.metadata.get("js_files", [])
        js_urls.extend(meta_js)

        client = self._get_client()
        try:
            resp = await client.request("GET", target.url)
            html = getattr(resp, "text", "") or ""

            # DAST-H1: directory listing detection
            for pattern in _DIRECTORY_LISTING_PATTERNS:
                if pattern.search(html):
                    target.metadata["directory_listing_detected"] = True
                    break

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
        """Parse a single JS file for URLs, secrets, source maps, and body params."""
        base = target.url

        # URLs
        for pattern in _URL_PATTERNS:
            for m in pattern.finditer(source):
                url = m.group(1)
                if self._is_valid_url(url):
                    if url.startswith("/"):
                        url = urljoin(base, url)
                    result.urls.add(url)

        # Body parameter names (DAST-H2) — skip common noise tokens
        _PARAM_NOISE = frozenset({
            "id", "type", "name", "value", "data", "key", "url", "title",
            "content", "text", "body", "status", "code", "message", "error",
            "token", "action", "method", "params", "query", "page", "size",
            "limit", "offset", "sort", "order", "filter", "from", "to",
        })
        for pattern in _BODY_FIELD_PATTERNS:
            for m in pattern.finditer(source):
                raw = m.group(1) if pattern.groups else ""
                if not raw:
                    continue
                # For GraphQL variables block, extract individual keys
                if "{" not in raw:
                    if raw not in _PARAM_NOISE and len(raw) >= 3:
                        result.body_params.add(raw)
                else:
                    for km in re.finditer(r'["\'`]?(\w{3,40})["\'`]?\s*:', raw):
                        param = km.group(1)
                        if param not in _PARAM_NOISE:
                            result.body_params.add(param)

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
