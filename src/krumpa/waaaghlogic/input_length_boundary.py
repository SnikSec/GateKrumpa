"""
WaaaghLogic — Input length boundary testing.

Empty inputs, max+1, very long strings, Unicode edge cases,
multi-byte truncation attacks.

CWE-120: Buffer Copy without Checking Size of Input
CWE-20: Improper Input Validation
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.input_length_boundary")

# Length test categories
_EMPTY_VALUES: List[Dict[str, Any]] = [
    {"label": "Empty string", "value": ""},
    {"label": "Whitespace only", "value": "   "},
    {"label": "Tab only", "value": "\t"},
    {"label": "Newline only", "value": "\n"},
    {"label": "Null char only", "value": "\x00"},
]

_LONG_VALUES: List[Dict[str, Any]] = [
    {"label": "256 chars", "value": "A" * 256},
    {"label": "1024 chars", "value": "B" * 1024},
    {"label": "4096 chars", "value": "C" * 4096},
    {"label": "65536 chars", "value": "D" * 65536},
    {"label": "1MB string", "value": "E" * (1024 * 1024)},
]

_UNICODE_EDGE_CASES: List[Dict[str, Any]] = [
    {"label": "Emoji", "value": "\U0001f4a9" * 100},
    {"label": "Zero-width joiner", "value": "a\u200db" * 100},
    {"label": "Right-to-left override", "value": "\u202eadmin\u202c"},
    {"label": "Combining chars", "value": "a\u0300\u0301\u0302\u0303\u0304" * 50},
    {"label": "Halfwidth katakana", "value": "\uff71\uff72\uff73" * 100},
    {"label": "4-byte UTF-8 (CJK ext B)", "value": "\U00020000" * 100},
    {"label": "Homoglyph 'a'→'а'", "value": "\u0430dmin"},
    {"label": "BOM prefix", "value": "\ufefftest"},
    {"label": "Null + valid", "value": "\x00valid"},
    {"label": "Multi-byte truncation", "value": "A" * 253 + "\U0001f600"},
]

# Common boundary sizes (typical DB column / form constraints)
_BOUNDARY_SIZES = [127, 128, 255, 256, 511, 512, 1023, 1024]


class InputLengthBoundaryTester(HttpClientMixin):
    """
    Test endpoints for input length boundary issues:
      1. Empty / whitespace-only inputs
      2. Maximum length + 1 (boundary overflow)
      3. Very long inputs (buffer overflow / DoS)
      4. Unicode edge cases (multi-byte truncation, homoglyphs, RTL)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def test(self, target: Target) -> List[Finding]:
        """Run all input length boundary tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=15.0, retries=0)

        try:
            findings.extend(await self._test_empty_values(client, target))
            findings.extend(await self._test_long_values(client, target))
            findings.extend(await self._test_boundary_values(client, target))
            findings.extend(await self._test_unicode_edge_cases(client, target))
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_empty_values(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send empty / whitespace-only inputs."""
        findings: List[Finding] = []
        test_fields = ["name", "email", "username", "value", "query", "search"]

        for field_name in test_fields:
            for payload in _EMPTY_VALUES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Empty input causes server error on {target.url}",
                            description=(
                                f"Sending {payload['label']} for '{field_name}' "
                                f"triggered a {resp.status_code} error. The server "
                                f"fails to handle empty/whitespace-only input."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}\n"
                                f"Input: {repr(payload['value'])}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Validate all inputs for empty/whitespace values "
                                "before processing. Return 400 Bad Request for "
                                "invalid inputs."
                            ),
                            cwe=20,
                            tags=["input-length", "empty-value", "waaaghlogic"],
                        ))
                        return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_long_values(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send very long strings to detect buffer issues or DoS."""
        findings: List[Finding] = []
        test_fields = ["name", "email", "description", "comment", "value"]

        for field_name in test_fields:
            for payload in _LONG_VALUES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Long input crash ({payload['label']}) on {target.url}",
                            description=(
                                f"Sending a {payload['label']} string for '{field_name}' "
                                f"triggered a {resp.status_code} server error. "
                                f"Unbounded input length can cause memory exhaustion, "
                                f"database errors, or buffer overflows."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}\n"
                                f"Length: {len(payload['value'])} chars\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Enforce maximum input length at the API level. "
                                "Use schema validation with maxLength constraints. "
                                "Limit request body size at the web server / proxy."
                            ),
                            cwe=120,
                            tags=["input-length", "long-string", "waaaghlogic"],
                        ))
                        return findings
                    # 200 with 1MB string accepted silently is also interesting
                    if (
                        resp.status_code in (200, 201)
                        and len(payload["value"]) >= 65536
                    ):
                        findings.append(Finding(
                            title=f"Extremely long input accepted on {target.url}",
                            description=(
                                f"The endpoint accepted a {payload['label']} string "
                                f"({len(payload['value'])} chars) for '{field_name}' "
                                f"without rejection. This may cause storage bloat "
                                f"or downstream processing issues."
                            ),
                            severity=Severity.LOW,
                            target=target,
                            evidence=(
                                f"Field: {field_name}\n"
                                f"Length: {len(payload['value'])} chars\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Enforce reasonable maximum input lengths for all fields."
                            ),
                            cwe=20,
                            tags=["input-length", "no-limit", "waaaghlogic"],
                        ))
                        return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_boundary_values(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test exact boundary sizes (127/128, 255/256, etc.)."""
        findings: List[Finding] = []
        test_fields = ["name", "username", "email", "title"]

        for field_name in test_fields:
            prev_status = None
            for size in _BOUNDARY_SIZES:
                body = {field_name: "A" * size}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if prev_status is not None:
                        # Detect boundary: success at N-1, failure at N
                        if prev_status in (200, 201) and resp.status_code >= 400:
                            findings.append(Finding(
                                title=f"Length boundary at {size} chars for '{field_name}' on {target.url}",
                                description=(
                                    f"The field '{field_name}' has a length limit between "
                                    f"{size // 2} and {size} characters. Requests beyond "
                                    f"this boundary return {resp.status_code}. This boundary "
                                    f"should be documented and enforced consistently."
                                ),
                                severity=Severity.INFO,
                                target=target,
                                evidence=(
                                    f"Field: {field_name}\n"
                                    f"Boundary: ~{size} chars\n"
                                    f"Status at boundary: {resp.status_code}"
                                ),
                                remediation=(
                                    "Document field length limits in API docs. "
                                    "Return descriptive error messages for oversized input."
                                ),
                                cwe=20,
                                tags=["input-length", "boundary", "waaaghlogic"],
                            ))
                            break
                    prev_status = resp.status_code
                except (httpx.HTTPError, OSError, ValueError):
                    prev_status = None
                    continue

        return findings

    async def _test_unicode_edge_cases(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send Unicode edge cases to detect encoding issues."""
        findings: List[Finding] = []
        test_fields = ["name", "username", "comment", "value"]

        for field_name in test_fields:
            for payload in _UNICODE_EDGE_CASES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Unicode edge case crash ({payload['label']}) on {target.url}",
                            description=(
                                f"Sending {payload['label']} for '{field_name}' "
                                f"triggered a {resp.status_code} server error. "
                                f"This may indicate encoding mismatch between "
                                f"application layer and database, or unsafe "
                                f"string operations."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}\n"
                                f"Payload: {payload['label']}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Use UTF-8 throughout the stack. Validate and "
                                "normalize Unicode input (NFC/NFKC). Handle "
                                "multi-byte characters correctly in length checks."
                            ),
                            cwe=176,
                            tags=["input-length", "unicode", "waaaghlogic"],
                        ))
                        return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings
