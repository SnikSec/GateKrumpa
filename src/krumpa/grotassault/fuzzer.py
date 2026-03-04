"""
GrotAssault — fuzz executor and anomaly detector.

Sends mutated payloads to target endpoints and flags anomalous responses:
  - HTTP 500+ server errors
  - Timeout / connection-reset (potential crash)
  - Stack traces or debug info in response bodies
  - Significant response-size deviations from baseline
  - Reflected input (potential XSS)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin
from krumpa.grotassault.mutator import Mutator

logger = logging.getLogger("krumpa.grotassault.fuzzer")

# ------------------------------------------------------------------
# Anomaly detection patterns
# ------------------------------------------------------------------

_STACK_TRACE_PATTERNS: List[re.Pattern] = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at [\w.]+\([\w]+\.java:\d+\)", re.IGNORECASE),
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"Fatal error:.*on line \d+", re.IGNORECASE),
    re.compile(r"Microsoft .NET Framework.*Error", re.IGNORECASE),
    re.compile(r"Stack Trace:", re.IGNORECASE),
    re.compile(r"<b>Warning</b>:.*on line <b>\d+</b>", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"MySQL.*syntax|error.*MySQL", re.IGNORECASE),
    re.compile(r"pg_query\(\):|pg_exec\(\):", re.IGNORECASE),
    re.compile(r"SQLite.*error", re.IGNORECASE),
]

_REFLECTION_MIN_LENGTH = 6  # only flag reflected strings of this length+


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class FuzzTarget(HttpClientMixin):
    """Specification for a fuzz target."""
    url: str
    method: str = "POST"
    base_body: Optional[Dict[str, Any]] = None
    base_headers: Optional[Dict[str, str]] = None
    fuzz_fields: List[str] = field(default_factory=list)
    # If empty, all keys in base_body are fuzzed
    fuzz_headers: List[str] = field(default_factory=list)


@dataclass
class _FuzzResult(HttpClientMixin):
    """Internal result of a single fuzz request."""
    payload: Any
    field: str
    status_code: int
    body: str
    response_size: int
    elapsed_ms: float
    error: Optional[str] = None


# ------------------------------------------------------------------
# Fuzzer
# ------------------------------------------------------------------

class Fuzzer(HttpClientMixin):
    """
    Send mutated payloads and detect anomalies.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    mutator:
        Optional :class:`Mutator` instance. A default one is created.
    baseline_deviation_pct:
        Response-size deviation (%) from baseline that triggers a finding.
    timeout_threshold_ms:
        Response time (ms) above which the request is flagged as slow.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        mutator: Optional[Mutator] = None,
        baseline_deviation_pct: float = 200.0,
        timeout_threshold_ms: float = 5000.0,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._mutator = mutator or Mutator(max_payloads_per_field=30)
        self.baseline_deviation_pct = baseline_deviation_pct
        self.timeout_threshold_ms = timeout_threshold_ms

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fuzz(self, fuzz_target: FuzzTarget, target: Target) -> List[Finding]:
        """
        Fuzz *fuzz_target* and return findings for any anomalies.
        """
        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            findings: List[Finding] = []

            # 1. Establish baseline
            baseline = await self._get_baseline(client, fuzz_target)

            # 2. Fuzz body fields
            fields = fuzz_target.fuzz_fields or list((fuzz_target.base_body or {}).keys())
            for field_name in fields:
                seed = (fuzz_target.base_body or {}).get(field_name, "")
                payloads = self._mutator.generate(seed)
                for payload in payloads:
                    result = await self._send_fuzzed(
                        client, fuzz_target, field_name, payload, location="body",
                    )
                    findings.extend(self._analyse(result, baseline, target))

            # 3. Fuzz headers
            for header_name in fuzz_target.fuzz_headers:
                payloads = self._mutator.generate(
                    (fuzz_target.base_headers or {}).get(header_name, ""),
                )
                for payload in payloads:
                    result = await self._send_fuzzed(
                        client, fuzz_target, header_name, payload, location="header",
                    )
                    findings.extend(self._analyse(result, baseline, target))

            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    async def _get_baseline(
        self, client: HttpClient, ft: FuzzTarget,
    ) -> _FuzzResult:
        """Send the unmodified request to establish normal behaviour."""
        start = time.monotonic()
        try:
            resp = await client.request(
                ft.method, ft.url,
                headers=ft.base_headers,
                json_body=ft.base_body,
            )
            elapsed = (time.monotonic() - start) * 1000
            return _FuzzResult(
                payload=None, field="baseline",
                status_code=resp.status_code, body=resp.text,
                response_size=len(resp.text), elapsed_ms=elapsed,
            )
        except (httpx.HTTPError, OSError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return _FuzzResult(
                payload=None, field="baseline",
                status_code=0, body="", response_size=0,
                elapsed_ms=elapsed, error=str(exc),
            )

    # ------------------------------------------------------------------
    # Fuzz dispatch
    # ------------------------------------------------------------------

    async def _send_fuzzed(
        self,
        client: HttpClient,
        ft: FuzzTarget,
        field_name: str,
        payload: Any,
        *,
        location: str,
    ) -> _FuzzResult:
        """Send a single fuzzed request."""
        body = dict(ft.base_body) if ft.base_body else {}
        headers = dict(ft.base_headers) if ft.base_headers else {}

        if location == "body":
            body[field_name] = payload
        else:
            headers[field_name] = str(payload)

        start = time.monotonic()
        try:
            resp = await client.request(
                ft.method, ft.url,
                headers=headers or None,
                json_body=body or None,
            )
            elapsed = (time.monotonic() - start) * 1000
            return _FuzzResult(
                payload=payload, field=field_name,
                status_code=resp.status_code, body=resp.text,
                response_size=len(resp.text), elapsed_ms=elapsed,
            )
        except (httpx.HTTPError, OSError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return _FuzzResult(
                payload=payload, field=field_name,
                status_code=0, body="", response_size=0,
                elapsed_ms=elapsed, error=str(exc),
            )

    # ------------------------------------------------------------------
    # Anomaly analysis
    # ------------------------------------------------------------------

    def _analyse(
        self,
        result: _FuzzResult,
        baseline: _FuzzResult,
        target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []
        payload_repr = repr(result.payload)[:120]

        # 1. Server error
        if result.status_code >= 500:
            findings.append(Finding(
                title=f"Server error ({result.status_code}) on field '{result.field}'",
                description=(
                    f"Payload {payload_repr} in field '{result.field}' caused "
                    f"HTTP {result.status_code}."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Payload: {payload_repr} → {result.status_code}",
                remediation="Investigate the server error; ensure input validation prevents crashes.",
                cwe=20,
                tags=["fuzz", "server-error"],
            ))

        # 2. Connection error (potential crash)
        if result.error:
            findings.append(Finding(
                title=f"Connection error fuzzing field '{result.field}'",
                description=(
                    f"Payload {payload_repr} caused a connection error: {result.error}. "
                    "The service may have crashed."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=f"Payload: {payload_repr} → error: {result.error}",
                remediation="Check if the service crashed; add input length and character validation.",
                cwe=20,
                tags=["fuzz", "crash"],
            ))

        # 3. Stack trace / debug info
        if result.body and self._has_stack_trace(result.body):
            findings.append(Finding(
                title=f"Stack trace leaked on field '{result.field}'",
                description=(
                    f"Payload {payload_repr} triggered a response containing "
                    "a stack trace or debug information."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Payload: {payload_repr}",
                remediation="Disable detailed error messages in production.",
                cwe=209,
                tags=["fuzz", "info-leak", "stack-trace"],
            ))

        # 4. Significant size deviation
        if (
            baseline.response_size > 0
            and result.response_size > 0
            and result.status_code > 0
        ):
            deviation = abs(result.response_size - baseline.response_size) / baseline.response_size * 100
            if deviation > self.baseline_deviation_pct:
                findings.append(Finding(
                    title=f"Response size anomaly on field '{result.field}' ({deviation:.0f}% deviation)",
                    description=(
                        f"Payload {payload_repr} produced a response of "
                        f"{result.response_size} bytes vs baseline {baseline.response_size} bytes "
                        f"({deviation:.0f}% deviation)."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=f"Payload: {payload_repr}, size: {result.response_size} vs {baseline.response_size}",
                    tags=["fuzz", "size-anomaly"],
                ))

        # 5. Reflected payload (XSS indicator)
        if (
            result.body
            and isinstance(result.payload, str)
            and len(result.payload) >= _REFLECTION_MIN_LENGTH
            and result.payload in result.body
        ):
            findings.append(Finding(
                title=f"Reflected input on field '{result.field}'",
                description=(
                    f"The payload {payload_repr} was reflected verbatim in the "
                    "response body, indicating potential XSS."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Payload: {payload_repr}",
                remediation="Encode all user input before rendering in responses.",
                cwe=79,
                tags=["fuzz", "reflection", "xss"],
            ))

        # 6. Slow response (potential time-based injection)
        if (
            result.elapsed_ms > self.timeout_threshold_ms
            and baseline.elapsed_ms > 0
            and result.elapsed_ms > baseline.elapsed_ms * 3
        ):
            findings.append(Finding(
                title=f"Slow response on field '{result.field}' ({result.elapsed_ms:.0f}ms)",
                description=(
                    f"Payload {payload_repr} took {result.elapsed_ms:.0f}ms "
                    f"(baseline: {baseline.elapsed_ms:.0f}ms). This may indicate "
                    "a time-based injection."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Payload: {payload_repr}, time: {result.elapsed_ms:.0f}ms",
                cwe=89,
                tags=["fuzz", "timing", "injection"],
            ))

        return findings

    @staticmethod
    def _has_stack_trace(body: str) -> bool:
        """Return True if the body contains known stack-trace patterns."""
        for pattern in _STACK_TRACE_PATTERNS:
            if pattern.search(body):
                return True
        return False
