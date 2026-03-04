"""
SneakyGits — Information leakage scanner.

Detects accidental information disclosure patterns:
  - Stack traces / debug output in responses
  - Internal IP addresses leaked in headers / bodies
  - Debug endpoints left accessible (e.g. /debug, /trace, /actuator)
  - Server version banners with patch-level detail
  - Source code comments in HTML
  - Error messages revealing backend internals

References:
  - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  - CWE-209: Generation of Error Message Containing Sensitive Information
  - OWASP Testing Guide: OTG-ERR-001, OTG-INFO-002
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.info_leakage")


# -- Regex patterns for common stack traces / errors -----------------------

_STACK_TRACE_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at\s+[\w$.]+\([\w]+\.java:\d+\)", re.IGNORECASE),  # Java
    re.compile(r"at\s+[\w\\/.]+\.cs:line\s+\d+", re.IGNORECASE),     # .NET
    re.compile(r"File\s+\"[^\"]+\",\s+line\s+\d+", re.IGNORECASE),   # Python
    re.compile(r"in\s+/[\w/]+\.php\s+on\s+line\s+\d+", re.IGNORECASE),  # PHP
    re.compile(r"at\s+Object\.<anonymous>\s+\([\w/.]+:\d+:\d+\)", re.IGNORECASE),  # Node
    re.compile(r"SQLSTATE\[\w+\]", re.IGNORECASE),  # PDO / SQL errors
    re.compile(r"(?:ORA|PLS)-\d{4,5}", re.IGNORECASE),  # Oracle errors
    re.compile(r"Microsoft OLE DB Provider", re.IGNORECASE),
    re.compile(r"pg_query\(\):", re.IGNORECASE),  # PostgreSQL
    re.compile(r"mysql_(?:fetch|query|connect)", re.IGNORECASE),
]

# Internal / private IP address patterns
_INTERNAL_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Headers that commonly leak internal details
_LEAKY_HEADERS: Dict[str, str] = {
    "X-Powered-By": "Server framework version disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
    "X-Runtime": "Server processing time leaked",
    "X-Debug-Token": "Symfony debug token exposed",
    "X-Debug-Token-Link": "Symfony debug profiler link exposed",
}

# Well-known debug / health endpoints to probe
_DEBUG_PATHS: List[str] = [
    "/.env",
    "/debug",
    "/debug/vars",
    "/debug/pprof/",
    "/trace",
    "/_profiler",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/configprops",
    "/__debug__/",
    "/server-status",
    "/server-info",
    "/info",
    "/phpinfo.php",
    "/elmah.axd",
    "/config.json",
    "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/web.config",
    "/crossdomain.xml",
]

# HTML comment patterns that may leak sensitive info
_COMMENT_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"<!--\s*(?:TODO|FIXME|HACK|BUG|XXX|PASSWORD|SECRET|KEY|TOKEN)[:\s]", re.IGNORECASE),
    re.compile(r"<!--.*(?:password|secret|api[_-]?key|token)\s*[:=]", re.IGNORECASE),
]


class InfoLeakageScanner(HttpClientMixin):
    """Detect information leakage across HTTP responses and debug endpoints."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        check_debug_paths: bool = True,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._check_debug_paths = check_debug_paths

    async def scan(self, target: Target) -> List[Finding]:
        """Run all information leakage checks on *target*."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=1)
        try:
            # Fetch the target page
            try:
                resp = await client.get(target.url)
            except (httpx.HTTPError, OSError, ValueError):
                return findings

            # 1. Stack trace / error patterns in body
            findings.extend(self._check_stack_traces(resp.text, target))

            # 2. Internal IPs in body
            findings.extend(self._check_internal_ips(resp.text, target, "body"))

            # 3. Internal IPs in headers
            header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            findings.extend(self._check_internal_ips(header_text, target, "headers"))

            # 4. Leaky headers
            findings.extend(self._check_leaky_headers(dict(resp.headers), target))

            # 5. HTML comments with sensitive info
            findings.extend(self._check_html_comments(resp.text, target))

            # 6. Debug endpoint probing
            if self._check_debug_paths:
                findings.extend(await self._probe_debug_paths(client, target))

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_stack_traces(body: str, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in _STACK_TRACE_PATTERNS:
            match = pattern.search(body)
            if match:
                snippet = body[max(0, match.start() - 40):match.end() + 80]
                findings.append(Finding(
                    title=f"Stack trace / error details exposed on {target.host}",
                    description=(
                        "Response contains a stack trace or detailed error message "
                        "that could help an attacker understand the backend."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=snippet[:300],
                    remediation=(
                        "Configure the application to show generic error pages "
                        "in production. Ensure DEBUG mode is disabled."
                    ),
                    cwe=209,
                    tags=["info-leakage", "stack-trace", "error-detail"],
                ))
                break  # one finding per target is enough
        return findings

    @staticmethod
    def _check_internal_ips(
        text: str, target: Target, location: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        ips = set(_INTERNAL_IP_RE.findall(text))
        if ips:
            findings.append(Finding(
                title=f"Internal IP address leaked in {location} on {target.host}",
                description=(
                    f"Internal / private IP addresses found in {location}: "
                    f"{', '.join(sorted(ips))}. This reveals internal network topology."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=f"IPs: {', '.join(sorted(ips))}",
                remediation="Strip internal IP addresses from responses and headers.",
                cwe=200,
                tags=["info-leakage", "internal-ip"],
            ))
        return findings

    @staticmethod
    def _check_leaky_headers(
        headers: Dict[str, str], target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []
        leaks: List[str] = []
        for hdr, desc in _LEAKY_HEADERS.items():
            for actual_name, actual_value in headers.items():
                if actual_name.lower() == hdr.lower():
                    leaks.append(f"{actual_name}: {actual_value} — {desc}")
        if leaks:
            findings.append(Finding(
                title=f"Information-leaking headers on {target.host}",
                description=(
                    "Response includes headers that disclose internal details:\n"
                    + "\n".join(leaks)
                ),
                severity=Severity.LOW,
                target=target,
                evidence="\n".join(leaks),
                remediation=(
                    "Remove or suppress X-Powered-By, X-AspNet-Version, "
                    "X-Debug-Token and similar headers in production."
                ),
                cwe=200,
                tags=["info-leakage", "headers"],
            ))
        return findings

    @staticmethod
    def _check_html_comments(body: str, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in _COMMENT_PATTERNS:
            match = pattern.search(body)
            if match:
                snippet = body[match.start():min(match.start() + 200, len(body))]
                findings.append(Finding(
                    title=f"Sensitive HTML comment on {target.host}",
                    description=(
                        "An HTML comment contains potentially sensitive information "
                        "(TODO, password, secret, key, etc.)."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=snippet[:200],
                    remediation="Remove sensitive comments from production HTML output.",
                    cwe=615,
                    tags=["info-leakage", "html-comment"],
                ))
                break
        return findings

    async def _probe_debug_paths(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Probe well-known debug/admin paths."""
        findings: List[Finding] = []
        from urllib.parse import urljoin

        for path in _DEBUG_PATHS:
            url = urljoin(target.url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append(Finding(
                        title=f"Debug/admin endpoint accessible: {path}",
                        description=(
                            f"The endpoint {url} returned HTTP 200 with "
                            f"{len(resp.text)} bytes. This may expose sensitive "
                            f"configuration or debug information."
                        ),
                        severity=Severity.MEDIUM,
                        target=Target(url=url, method="GET"),
                        evidence=f"HTTP 200, {len(resp.text)} bytes",
                        remediation=(
                            "Restrict debug endpoints to internal networks. "
                            "Disable debug mode in production. Remove "
                            "development artifacts (.env, .git, phpinfo)."
                        ),
                        cwe=200,
                        tags=["info-leakage", "debug-endpoint", "recon"],
                    ))
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings
