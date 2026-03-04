"""
Web cache poisoning — unkeyed headers, query string poisoning,
fat GET, host header override, and cache-key normalization attacks.

CWE-444: Inconsistent Interpretation of HTTP Requests
CWE-345: Insufficient Verification of Data Authenticity
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Unkeyed headers commonly exploitable for cache poisoning
# ------------------------------------------------------------------

_UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil-{canary}.example.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/{canary}"),
    ("X-Rewrite-URL", "/{canary}"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-For", "127.0.0.{canary_short}"),
    ("X-Host", "evil-{canary}.example.com"),
    ("X-Forwarded-Server", "evil-{canary}.example.com"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Original-Host", "evil-{canary}.example.com"),
    ("Forwarded", "host=evil-{canary}.example.com"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("Fastly-Client-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-WAP-Profile", "http://evil-{canary}.example.com/wap.xml"),
]


@dataclass
class CacheBuster:
    """Unique parameter to ensure cache miss on each probe."""
    param: str = "cb"

    def bust(self) -> str:
        return secrets.token_hex(6)


class CachePoisonChecker:
    """
    Tests for web cache poisoning vulnerabilities by injecting
    unkeyed headers and observing response reflection + caching.
    """

    def __init__(self, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is not None
        self._buster = CacheBuster()

    async def check(self, target: Target) -> List[Finding]:
        """Run all cache poisoning checks against *target*."""
        client = self._client
        if client is None:
            return []

        findings: List[Finding] = []
        url = target.url

        findings.extend(await self._test_unkeyed_headers(client, url, target))
        findings.extend(await self._test_fat_get(client, url, target))
        findings.extend(await self._test_query_string_poisoning(client, url, target))
        findings.extend(await self._test_parameter_cloaking(client, url, target))
        findings.extend(await self._test_method_override_cache(client, url, target))

        return findings

    # ----------------------------------------------------------
    # Unkeyed header reflection
    # ----------------------------------------------------------

    async def _test_unkeyed_headers(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for header_name, value_template in _UNKEYED_HEADERS:
            canary = secrets.token_hex(8)
            canary_short = str(secrets.randbelow(254) + 1)
            value = value_template.format(canary=canary, canary_short=canary_short)

            cb = self._buster.bust()
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{self._buster.param}={cb}"

            try:
                # 1. Send poisoned request
                resp = await client.request(
                    "GET", probe_url,
                    headers={header_name: value},
                )

                if resp.status_code not in range(200, 400):
                    continue

                body = resp.text
                reflected = canary in body or value in body

                if not reflected:
                    continue

                # 2. Check if the poisoned response was cached
                # Send a clean request with same cache buster
                resp2 = await client.request("GET", probe_url)

                if resp2.status_code in range(200, 400):
                    body2 = resp2.text
                    if canary in body2 or value in body2:
                        findings.append(Finding(
                            title=f"Cache poisoning via {header_name}",
                            description=(
                                f"The unkeyed header '{header_name}' was reflected in the "
                                f"response and the poisoned response was served from cache "
                                f"on a subsequent clean request."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Header: {header_name}: {value}\n"
                                f"Canary: {canary}\n"
                                f"Reflected in cached response: True"
                            ),
                            remediation=(
                                "Include all reflected headers in the cache key, or "
                                "avoid reflecting unkeyed request components in responses."
                            ),
                            cwe=444,
                            tags=["cache-poisoning", "unkeyed-header", "grotassault"],
                        ))
                    elif reflected:
                        # Reflected but not cached — still noteworthy
                        findings.append(Finding(
                            title=f"Unkeyed header reflected: {header_name}",
                            description=(
                                f"The header '{header_name}' is reflected in the response "
                                f"but the reflection was NOT observed in the cache. "
                                f"May still be exploitable under different caching conditions."
                            ),
                            severity=Severity.LOW,
                            target=target,
                            evidence=f"Header: {header_name}: {value}\nReflected: True\nCached: False",
                            remediation="Avoid reflecting unkeyed headers in responses.",
                            cwe=444,
                            tags=["cache-poisoning", "unkeyed-header", "grotassault"],
                        ))

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ----------------------------------------------------------
    # Fat GET — body in GET request
    # ----------------------------------------------------------

    async def _test_fat_get(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        """Some servers allow body in GET requests, overriding query params."""
        canary = secrets.token_hex(8)

        try:
            # Send GET with a body
            resp = await client.request(
                "GET", url,
                body=f'{{"search":"{canary}"}}',
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code in range(200, 400) and canary in resp.text:
                return [Finding(
                    title="Fat GET body reflected in response",
                    description=(
                        "The server accepted and processed a body in a GET request. "
                        "If the cache ignores GET bodies (most do), this can be used "
                        "to poison cached responses."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Canary: {canary}\nReflected in GET body response: True",
                    remediation="Reject or ignore request bodies on GET endpoints.",
                    cwe=444,
                    tags=["cache-poisoning", "fat-get", "grotassault"],
                )]

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return []

    # ----------------------------------------------------------
    # Query string poisoning — unkeyed query params
    # ----------------------------------------------------------

    async def _test_query_string_poisoning(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        """Test if extra query params are reflected but not part of the cache key."""
        canary = secrets.token_hex(8)
        findings: List[Finding] = []

        # UTM and tracking params often unkeyed
        unkeyed_params = [
            "utm_source", "utm_medium", "utm_campaign", "utm_content",
            "fbclid", "gclid", "mc_cid", "mc_eid",
            "_ga", "ref", "source",
        ]

        for param in unkeyed_params:
            cb = self._buster.bust()
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{self._buster.param}={cb}&{param}={canary}"

            try:
                resp = await client.request("GET", probe_url)

                if resp.status_code not in range(200, 400):
                    continue

                if canary not in resp.text:
                    continue

                # Check if cached without the param
                clean_url = f"{url}{sep}{self._buster.param}={cb}"
                resp2 = await client.request("GET", clean_url)

                if resp2.status_code in range(200, 400) and canary in resp2.text:
                    findings.append(Finding(
                        title=f"Cache poisoning via unkeyed parameter: {param}",
                        description=(
                            f"The query parameter '{param}' was reflected in the response "
                            f"and the poisoned content appeared in a subsequent request "
                            f"without the parameter, indicating it's not part of the cache key."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Parameter: {param}\nCanary: {canary}\nCached: True",
                        remediation="Ensure all reflected query parameters are included in the cache key.",
                        cwe=444,
                        tags=["cache-poisoning", "query-string", "grotassault"],
                    ))
                    break

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ----------------------------------------------------------
    # Parameter cloaking — semicolon vs ampersand parsing
    # ----------------------------------------------------------

    async def _test_parameter_cloaking(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        """
        Test for parameter cloaking via differing delimiter interpretation.
        Cache sees one param (;), app sees another (&).
        """
        canary = secrets.token_hex(8)
        cb = self._buster.bust()
        sep = "&" if "?" in url else "?"

        # Semicolon cloaking: cache sees `cb=X;injected=canary` as one param
        probe_url = f"{url}{sep}{self._buster.param}={cb};injected={canary}"

        try:
            resp = await client.request("GET", probe_url)

            if resp.status_code in range(200, 400) and canary in resp.text:
                return [Finding(
                    title="Parameter cloaking via semicolon delimiter",
                    description=(
                        "Server accepted a semicolon-delimited parameter that may be "
                        "invisible to the caching layer. Different parsing of ';' vs '&' "
                        "between cache and application enables cache poisoning."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Cloaked param: injected={canary}\nReflected: True",
                    remediation="Normalize parameter delimiters at the cache layer.",
                    cwe=444,
                    tags=["cache-poisoning", "parameter-cloaking", "grotassault"],
                )]

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return []

    # ----------------------------------------------------------
    # Method override + cache
    # ----------------------------------------------------------

    async def _test_method_override_cache(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        """Test if method override headers change behavior while cache keys only consider GET."""
        canary = secrets.token_hex(8)
        override_headers = [
            ("X-HTTP-Method-Override", "POST"),
            ("X-HTTP-Method", "POST"),
            ("X-Method-Override", "POST"),
        ]

        for header_name, method_val in override_headers:
            try:
                resp = await client.request(
                    "GET", url,
                    headers={header_name: method_val},
                    body=f'{{"test":"{canary}"}}',
                )

                if resp.status_code in range(200, 400):
                    # If the response differs from a normal GET
                    normal = await client.request("GET", url)
                    if resp.text != normal.text and canary in resp.text:
                        return [Finding(
                            title=f"Method override accepted via {header_name}",
                            description=(
                                f"The server treated a GET request as POST when "
                                f"'{header_name}: {method_val}' was sent. If the cache "
                                f"keys on GET, the POST response may be cached and served "
                                f"to other users."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Header: {header_name}: {method_val}\nBody reflected: True",
                            remediation="Reject or ignore method override headers, or include them in the cache key.",
                            cwe=444,
                            tags=["cache-poisoning", "method-override", "grotassault"],
                        )]

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return []
