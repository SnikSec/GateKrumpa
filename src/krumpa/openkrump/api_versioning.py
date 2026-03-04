"""API versioning detection — old versions still accessible, downgrade attacks.

Phase 4 item #60.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.openkrump.api_versioning")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class ApiVersion:
    """A detected API version."""
    version: str        # e.g., "v1", "v2", "2023-01-01"
    url: str
    status_code: int = 0
    response_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    is_deprecated: bool = False
    is_accessible: bool = False


# ------------------------------------------------------------------
# Version patterns
# ------------------------------------------------------------------

VERSION_PATH_PATTERNS = [
    # Numeric: /v1, /v2, /v3 ... /v20
    *[f"/v{n}" for n in range(1, 21)],
    # API prefix: /api/v1, /api/v2
    *[f"/api/v{n}" for n in range(1, 21)],
    # Date-based versions
    "/2020-01-01", "/2021-01-01", "/2022-01-01",
    "/2023-01-01", "/2024-01-01", "/2025-01-01",
    "/api/2020-01-01", "/api/2021-01-01", "/api/2022-01-01",
    "/api/2023-01-01", "/api/2024-01-01", "/api/2025-01-01",
]

VERSION_HEADER_NAMES = [
    "api-version",
    "x-api-version",
    "x-version",
    "accept-version",
    "api_version",
]

VERSION_QUERY_PARAMS = [
    "version",
    "api-version",
    "api_version",
    "v",
    "ver",
]


class ApiVersioningDetector(HttpClientMixin):
    """Detect accessible old API versions and downgrade attacks.

    Tests:
    - URL path-based version enumeration (/v1, /v2, etc.)
    - Header-based version negotiation
    - Query parameter-based versioning
    - Deprecated version accessibility
    - Version downgrade attack viability
    - Missing deprecation headers
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all API versioning checks."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        url = target.url
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Detect current version
        current_version = self._detect_current_version(url)

        # 2. Enumerate path-based versions
        versions = await self._enumerate_path_versions(base, target)

        # 3. Check header-based versioning
        header_versions = await self._enumerate_header_versions(url, target)
        versions.extend(header_versions)

        # 4. Check query-param-based versioning
        query_versions = await self._enumerate_query_versions(url, target)
        versions.extend(query_versions)

        # 5. Analyze findings
        accessible = [v for v in versions if v.is_accessible]

        if len(accessible) > 1:
            findings.extend(self._check_deprecated_versions(
                accessible, current_version, target,
            ))
            findings.extend(self._check_version_downgrade(
                accessible, current_version, target,
            ))

        # 6. Check for missing deprecation headers
        for v in accessible:
            if v.is_deprecated:
                findings.extend(
                    self._check_deprecation_headers(v, target)
                )

        return findings

    # ----------------------------------------------------------
    # Version detection
    # ----------------------------------------------------------

    @staticmethod
    def _detect_current_version(url: str) -> str:
        """Detect the version from the current URL."""
        m = re.search(r'/v(\d+)', url)
        if m:
            return f"v{m.group(1)}"
        m = re.search(r'/(\d{4}-\d{2}-\d{2})', url)
        if m:
            return m.group(1)
        return ""

    # ----------------------------------------------------------
    # Path-based enumeration
    # ----------------------------------------------------------

    async def _enumerate_path_versions(
        self, base: str, target: Target,
    ) -> List[ApiVersion]:
        """Enumerate API versions via URL paths."""
        versions: List[ApiVersion] = []
        seen: Set[str] = set()

        for path in VERSION_PATH_PATTERNS:
            probe_url = f"{base}{path}"
            if probe_url in seen:
                continue
            seen.add(probe_url)

            try:
                resp = await self._client.request("GET", probe_url)

                if resp.status_code in (200, 301, 302, 307, 308):
                    version_str = path.strip("/").split("/")[-1]
                    version = ApiVersion(
                        version=version_str,
                        url=probe_url,
                        status_code=resp.status_code,
                        response_size=len(resp.text),
                        headers=dict(resp.headers),
                        is_accessible=resp.status_code == 200,
                    )

                    # Check deprecation indicators
                    dep_header = resp.headers.get("deprecation", "")
                    sunset_header = resp.headers.get("sunset", "")
                    if dep_header or sunset_header:
                        version.is_deprecated = True

                    # Check for "deprecated" in response
                    if "deprecated" in resp.text.lower()[:500]:
                        version.is_deprecated = True

                    versions.append(version)

            except Exception:
                continue

        return versions

    # ----------------------------------------------------------
    # Header-based enumeration
    # ----------------------------------------------------------

    async def _enumerate_header_versions(
        self, url: str, target: Target,
    ) -> List[ApiVersion]:
        """Enumerate versions via header negotiation."""
        versions: List[ApiVersion] = []
        test_values = ["1", "2", "3", "v1", "v2", "v3",
                       "2020-01-01", "2023-01-01", "2024-01-01"]

        for header_name in VERSION_HEADER_NAMES:
            for val in test_values:
                try:
                    resp = await self._client.request(
                        "GET", url, headers={header_name: val},
                    )

                    if resp.status_code == 200:
                        api_ver = resp.headers.get("api-version",
                                  resp.headers.get("x-api-version", val))
                        versions.append(ApiVersion(
                            version=api_ver,
                            url=f"{url} [Header: {header_name}={val}]",
                            status_code=resp.status_code,
                            response_size=len(resp.text),
                            is_accessible=True,
                        ))
                        break  # Found a valid version header

                except Exception:
                    continue

        return versions

    # ----------------------------------------------------------
    # Query-param enumeration
    # ----------------------------------------------------------

    async def _enumerate_query_versions(
        self, url: str, target: Target,
    ) -> List[ApiVersion]:
        """Enumerate versions via query parameters."""
        versions: List[ApiVersion] = []
        test_values = ["1", "2", "3", "v1", "v2"]

        for param in VERSION_QUERY_PARAMS:
            for val in test_values:
                sep = "&" if "?" in url else "?"
                probe_url = f"{url}{sep}{param}={val}"

                try:
                    resp = await self._client.request("GET", probe_url)

                    if resp.status_code == 200:
                        versions.append(ApiVersion(
                            version=val,
                            url=probe_url,
                            status_code=resp.status_code,
                            response_size=len(resp.text),
                            is_accessible=True,
                        ))
                        break  # Found a valid version query param

                except Exception:
                    continue

        return versions

    # ----------------------------------------------------------
    # Analysis
    # ----------------------------------------------------------

    def _check_deprecated_versions(
        self,
        accessible: List[ApiVersion],
        current: str,
        target: Target,
    ) -> List[Finding]:
        """Check for deprecated but still accessible versions."""
        findings: List[Finding] = []

        old_versions = [v for v in accessible if v.is_deprecated]
        if not old_versions:
            # Even if not explicitly deprecated, older versions may be risky
            if current:
                old_versions = [
                    v for v in accessible
                    if v.version != current
                    and self._version_older_than(v.version, current)
                ]

        for v in old_versions:
            findings.append(Finding(
                title=f"Deprecated API version still accessible: {v.version}",
                description=(
                    f"API version '{v.version}' is accessible at {v.url}. "
                    f"Older API versions may lack security patches, rate limiting, "
                    f"or input validation present in newer versions."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=(
                    f"Version: {v.version}\n"
                    f"URL: {v.url}\n"
                    f"Status: {v.status_code}\n"
                    f"Response size: {v.response_size} bytes\n"
                    f"Current version: {current or 'unknown'}"
                ),
                remediation=(
                    "Decommission old API versions after a deprecation period. "
                    "Return 410 Gone or 301 redirect to the current version. "
                    "Add Sunset headers to deprecated versions."
                ),
                cwe=672,
                tags=["api-versioning", "deprecated", "openkrump"],
            ))

        return findings

    def _check_version_downgrade(
        self,
        accessible: List[ApiVersion],
        current: str,
        target: Target,
    ) -> List[Finding]:
        """Check if version downgrade attacks are possible."""
        findings: List[Finding] = []

        if len(accessible) < 2:
            return findings

        # Sort versions and check if older ones lack security features
        sorted_versions = sorted(accessible, key=lambda v: v.version)

        oldest = sorted_versions[0]
        newest = sorted_versions[-1]

        if oldest.version != newest.version:
            findings.append(Finding(
                title=f"API version downgrade possible: {oldest.version} → {newest.version}",
                description=(
                    f"Multiple API versions are simultaneously accessible. "
                    f"An attacker could force a client to use an older version "
                    f"({oldest.version}) that may lack security controls present "
                    f"in the current version ({newest.version})."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=(
                    f"Oldest accessible: {oldest.version} at {oldest.url}\n"
                    f"Newest accessible: {newest.version} at {newest.url}\n"
                    f"Total versions found: {len(accessible)}"
                ),
                remediation=(
                    "Implement version sunset policies. Disable old API versions. "
                    "If clients must specify versions, enforce minimum version "
                    "requirements. Use Deprecation and Sunset headers."
                ),
                cwe=757,
                tags=["api-versioning", "downgrade", "openkrump"],
            ))

        return findings

    def _check_deprecation_headers(
        self, version: ApiVersion, target: Target,
    ) -> List[Finding]:
        """Check for proper deprecation headers on deprecated versions."""
        findings: List[Finding] = []
        headers = version.headers

        missing = []
        if "deprecation" not in {k.lower() for k in headers}:
            missing.append("Deprecation")
        if "sunset" not in {k.lower() for k in headers}:
            missing.append("Sunset")

        if missing:
            findings.append(Finding(
                title=f"Missing deprecation headers on version {version.version}",
                description=(
                    f"Deprecated API version '{version.version}' is missing "
                    f"standard deprecation headers: {', '.join(missing)}. "
                    f"Clients may not realize they are using a deprecated version."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=(
                    f"Version: {version.version}\n"
                    f"URL: {version.url}\n"
                    f"Missing headers: {', '.join(missing)}"
                ),
                remediation=(
                    "Add RFC 8594 Deprecation and Sunset headers to deprecated "
                    "API versions. Include Link header pointing to the current version."
                ),
                cwe=200,
                tags=["api-versioning", "headers", "openkrump"],
            ))

        return findings

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    @staticmethod
    def _version_older_than(ver_a: str, ver_b: str) -> bool:
        """Simple heuristic comparison: is ver_a older than ver_b?"""
        # Extract numeric parts
        def extract_num(v: str) -> int:
            m = re.search(r'(\d+)', v)
            return int(m.group(1)) if m else 0

        return extract_num(ver_a) < extract_num(ver_b)
