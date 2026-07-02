"""
SneakyGits — passive reconnaissance and attack-surface expansion.

Provides three analyzers that collect URL and subdomain surface without
actively crawling the target:

- :class:`WaybackHarvester`         — archived URLs from Wayback Machine CDX API
- :class:`CommonCrawlHarvester`     — indexed URLs from Common Crawl CDX API
- :class:`ParameterMiner`           — parameter name candidates from archived URLs
- :class:`SubdomainTakeoverChecker` — dangling CNAME detection for common platforms

All HTTP calls use the shared :class:`HttpClient` and stay within the scope
enforcer embedded in the client.  Discovered targets are tagged
``discovered_by: passive_recon`` so downstream modules can distinguish them
from live-crawl findings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlencode, urlparse, parse_qs

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.passive_recon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
_COMMONCRAWL_INDEX = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"  # latest available

# Platforms with known dangling-CNAME takeover patterns
_TAKEOVER_FINGERPRINTS: List[Dict] = [
    {
        "name": "GitHub Pages",
        "cname_suffix": ".github.io",
        "body_pattern": re.compile(r"There isn.t a GitHub Pages site here", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Heroku",
        "cname_suffix": ".herokuapp.com",
        "body_pattern": re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Azure Web Apps",
        "cname_suffix": ".azurewebsites.net",
        "body_pattern": re.compile(r"404 Web Site not found|Microsoft Azure App Service", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "AWS CloudFront",
        "cname_suffix": ".cloudfront.net",
        "body_pattern": re.compile(r"The request could not be satisfied|ERROR.*The request could not be satisfied", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Fastly",
        "cname_suffix": ".fastly.net",
        "body_pattern": re.compile(r"Fastly error: unknown domain|Please check that this domain has been added", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Netlify",
        "cname_suffix": ".netlify.app",
        "body_pattern": re.compile(r"Not Found.*Netlify|does not exist|Page Not Found", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Vercel",
        "cname_suffix": ".vercel.app",
        "body_pattern": re.compile(r"The deployment could not be found|DEPLOYMENT_NOT_FOUND", re.IGNORECASE),
        "cwe": 350,
    },
    {
        "name": "Shopify",
        "cname_suffix": ".myshopify.com",
        "body_pattern": re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE),
        "cwe": 350,
    },
]


# ---------------------------------------------------------------------------
# Wayback Machine harvester
# ---------------------------------------------------------------------------

class WaybackHarvester(HttpClientMixin):
    """Query the Wayback Machine CDX API for archived URLs of a domain."""

    def __init__(self, *, http_client: Optional[HttpClient] = None, max_results: int = 500) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.max_results = max_results

    async def harvest(self, domain: str) -> List[str]:
        """Return a list of unique URLs archived for *domain*."""
        client = self._client or HttpClient(timeout=20.0, retries=2)
        try:
            params = {
                "url": f"*.{domain}",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "limit": str(self.max_results),
                "filter": "statuscode:200",
            }
            url = f"{_WAYBACK_CDX}?{urlencode(params)}"
            resp = await client.get(url)
            text = getattr(resp, "text", "") or ""
            urls: List[str] = []
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.append(line)
            logger.info("Wayback: %d archived URLs for %s", len(urls), domain)
            return urls
        except Exception as exc:
            logger.debug("Wayback harvest failed for %s: %s", domain, exc)
            return []
        finally:
            if self._owns_client and client is not self._client:
                await client.close()


# ---------------------------------------------------------------------------
# Common Crawl harvester
# ---------------------------------------------------------------------------

class CommonCrawlHarvester(HttpClientMixin):
    """Query the Common Crawl CDX index for URLs of a domain."""

    def __init__(self, *, http_client: Optional[HttpClient] = None, max_results: int = 300) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.max_results = max_results

    async def harvest(self, domain: str) -> List[str]:
        """Return a list of unique URLs from Common Crawl for *domain*."""
        client = self._client or HttpClient(timeout=20.0, retries=2)
        try:
            params = {
                "url": f"*.{domain}",
                "output": "text",
                "fl": "url",
                "limit": str(self.max_results),
            }
            url = f"{_COMMONCRAWL_INDEX}?{urlencode(params)}"
            resp = await client.get(url)
            text = getattr(resp, "text", "") or ""
            urls = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("http")]
            logger.info("CommonCrawl: %d URLs for %s", len(urls), domain)
            return urls
        except Exception as exc:
            logger.debug("CommonCrawl harvest failed for %s: %s", domain, exc)
            return []
        finally:
            if self._owns_client and client is not self._client:
                await client.close()


# ---------------------------------------------------------------------------
# Parameter miner
# ---------------------------------------------------------------------------

class ParameterMiner:
    """Extract parameter name candidates from a collection of URLs.

    Mines query-string parameter names and stores them as candidate
    inputs for ``grotassault`` fuzzing via ``Target.metadata["js_discovered_params"]``.
    """

    # Common noise params we don't want to flood grotassault with
    _NOISE: frozenset = frozenset({
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "fbclid", "gclid", "ref", "source", "cb", "v", "t", "ts", "r",
    })

    def mine(self, urls: List[str]) -> Set[str]:
        """Return a set of unique parameter names from *urls*."""
        params: Set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    for key in parse_qs(parsed.query):
                        if key not in self._NOISE and len(key) >= 2:
                            params.add(key)
            except Exception:
                continue
        return params


# ---------------------------------------------------------------------------
# Subdomain takeover checker
# ---------------------------------------------------------------------------

class SubdomainTakeoverChecker(HttpClientMixin):
    """Detect dangling CNAME records pointing at unregistered cloud services."""

    def __init__(self, *, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, subdomains: List[str]) -> List[Finding]:
        """Test each subdomain URL for subdomain takeover indicators.

        Parameters
        ----------
        subdomains:
            List of fully-qualified subdomain URLs (``https://sub.example.com``).
        """
        client = self._client or HttpClient(timeout=10.0, retries=1)
        findings: List[Finding] = []
        try:
            for sub_url in subdomains:
                parsed = urlparse(sub_url)
                host = parsed.hostname or ""
                for fp in _TAKEOVER_FINGERPRINTS:
                    if not host.endswith(fp["cname_suffix"]):
                        continue
                    # The CNAME points at a known cloud platform — check for
                    # the platform's "unclaimed" error page
                    try:
                        resp = await client.get(sub_url)
                        body = getattr(resp, "text", "") or ""
                        if fp["body_pattern"].search(body):
                            findings.append(Finding(
                                title=f"Subdomain takeover possible: {host} ({fp['name']})",
                                description=(
                                    f"The subdomain {host!r} has a CNAME pointing to "
                                    f"{fp['name']} but the resource is unclaimed. "
                                    f"An attacker could register the resource and serve "
                                    f"arbitrary content from this trusted subdomain."
                                ),
                                severity=Severity.HIGH,
                                target=Target(url=sub_url),
                                evidence=f"CNAME suffix: {fp['cname_suffix']}\n"
                                         f"Response body excerpt: {body[:200]}",
                                remediation=(
                                    f"Remove the dangling CNAME DNS record for {host!r} "
                                    f"or reclaim the resource on {fp['name']}."
                                ),
                                cwe=fp["cwe"],
                                tags=["recon", "passive-recon", "subdomain-takeover", fp["name"].lower().replace(" ", "-")],
                            ))
                    except Exception as exc:
                        logger.debug("Takeover check failed for %s: %s", sub_url, exc)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()
        return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class PassiveReconResult:
    """Aggregated output of all passive recon analyzers."""
    archived_urls: List[str] = field(default_factory=list)
    discovered_params: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)


class PassiveReconAnalyzer(HttpClientMixin):
    """Orchestrate Wayback, CommonCrawl, parameter mining, and takeover checks."""

    def __init__(self, *, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._wayback = WaybackHarvester()
        self._commoncrawl = CommonCrawlHarvester()
        self._param_miner = ParameterMiner()
        self._takeover_checker = SubdomainTakeoverChecker()

    async def analyze(self, target: Target) -> PassiveReconResult:
        """Run all passive recon checks for *target*."""
        result = PassiveReconResult()
        domain = _extract_domain(target.url)
        if not domain:
            return result

        # Wire shared client into sub-analyzers
        if self._client:
            self._wayback.set_client(self._client)
            self._commoncrawl.set_client(self._client)
            self._takeover_checker.set_client(self._client)

        # Harvest archived URLs from both sources
        wayback_urls = await self._wayback.harvest(domain)
        cc_urls = await self._commoncrawl.harvest(domain)
        all_archived = list({u for u in (wayback_urls + cc_urls) if u})
        result.archived_urls = all_archived

        # Mine parameter candidates
        result.discovered_params = self._param_miner.mine(all_archived)

        # Subdomain takeover — check subdomains found in archived URLs
        subdomains = _extract_subdomains(all_archived, domain)
        if subdomains:
            result.findings.extend(
                await self._takeover_checker.check(list(subdomains))
            )

        logger.info(
            "Passive recon for %s: %d archived URLs, %d param candidates, %d takeover findings",
            domain, len(all_archived), len(result.discovered_params), len(result.findings),
        )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Return the registered domain (host without subdomain) from a URL."""
    try:
        host = urlparse(url).hostname or ""
        # Strip 'www.' prefix; return the last two labels as the apex domain
        parts = host.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def _extract_subdomains(urls: List[str], apex_domain: str) -> Set[str]:
    """Return subdomain base-URLs found in *urls* that are children of *apex_domain*."""
    seen: Set[str] = set()
    for url in urls:
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower()
            if host.endswith(f".{apex_domain}") and host != apex_domain:
                base = f"{p.scheme}://{host}"
                seen.add(base)
        except Exception:
            continue
    return seen
