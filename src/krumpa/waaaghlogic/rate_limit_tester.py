"""
Business-layer rate-limit tester.

Sends bursts of requests to business-critical endpoints (purchases,
transfers, password changes, OTP/SMS sends) and checks whether the
server enforces per-user / per-action rate limits.

A missing or too-generous limit is a real-world abuse vector — attackers
can drain balances, enumerate codes, or trigger SMS-pump fraud.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.rate_limit")

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

# Default burst size (requests per burst)
_DEFAULT_BURST = 10

# Default concurrency (parallel requests within a burst)
_DEFAULT_CONCURRENCY = 5

# If ≥ this fraction of burst requests succeed, rate-limiting is absent
_DEFAULT_SUCCESS_THRESHOLD = 0.9

# HTTP status codes that indicate a successful (non-rate-limited) response
_SUCCESS_CODES = frozenset(range(200, 300))

# Status codes that indicate rate limiting is active
_RATE_LIMIT_CODES = frozenset({429, 503})


@dataclass
class RateLimitTarget:
    """Describes a single endpoint to probe for rate-limit enforcement."""

    url: str
    method: str = "POST"
    body: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    label: str = ""
    burst_size: int = _DEFAULT_BURST
    success_threshold: float = _DEFAULT_SUCCESS_THRESHOLD


@dataclass
class BurstResult:
    """Outcome of a single burst probe against one endpoint."""

    target: RateLimitTarget
    total_sent: int = 0
    success_count: int = 0
    rate_limited_count: int = 0
    error_count: int = 0
    status_codes: List[int] = field(default_factory=list)
    rate_limit_enforced: bool = False


class RateLimitTester(HttpClientMixin):
    """Probe business-critical endpoints for rate-limit enforcement.

    Fires a configurable burst of concurrent requests and records how
    many succeed vs. get ``429 Too Many Requests`` (or equivalent).
    A high success ratio means the endpoint lacks rate limiting.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        concurrency: int = _DEFAULT_CONCURRENCY,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.concurrency = concurrency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test(
        self,
        targets: List[RateLimitTarget],
        scan_target: Target,
    ) -> List[Finding]:
        """Run rate-limit probes and return any findings.

        Parameters
        ----------
        targets:
            Endpoints to test.  Each target specifies URL, method, body,
            burst size, and the threshold above which the endpoint is
            considered *unprotected*.
        scan_target:
            The owning :class:`Target` for attribution in findings.
        """
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            findings: List[Finding] = []
            for rt in targets:
                result = await self._burst_probe(client, rt)
                if not result.rate_limit_enforced:
                    findings.append(self._build_finding(result, scan_target))
            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _burst_probe(
        self,
        client: HttpClient,
        rt: RateLimitTarget,
    ) -> BurstResult:
        """Send *rt.burst_size* requests with bounded concurrency."""
        sem = asyncio.Semaphore(self.concurrency)
        result = BurstResult(target=rt)

        async def _fire() -> int:
            async with sem:
                resp = await client.request(
                    rt.method,
                    rt.url,
                    headers=rt.headers,
                    json_body=rt.body,
                )
                return resp.status_code

        tasks = [asyncio.create_task(_fire()) for _ in range(rt.burst_size)]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for outcome in outcomes:
            result.total_sent += 1
            if isinstance(outcome, BaseException):
                result.error_count += 1
                continue
            code: int = outcome
            result.status_codes.append(code)
            if code in _RATE_LIMIT_CODES:
                result.rate_limited_count += 1
            elif code in _SUCCESS_CODES:
                result.success_count += 1

        # Decide whether rate limiting was enforced
        if result.total_sent > 0:
            success_ratio = result.success_count / result.total_sent
            result.rate_limit_enforced = success_ratio < rt.success_threshold

        label = rt.label or f"{rt.method} {rt.url}"
        if result.rate_limit_enforced:
            logger.info(
                "Rate limiting detected on %s — %d/%d blocked",
                label,
                result.rate_limited_count,
                result.total_sent,
            )
        else:
            logger.warning(
                "No rate limiting on %s — %d/%d succeeded",
                label,
                result.success_count,
                result.total_sent,
            )

        return result

    @staticmethod
    def _build_finding(result: BurstResult, target: Target) -> Finding:
        label = result.target.label or f"{result.target.method} {result.target.url}"
        return Finding(
            title=f"Missing rate limit on {label}",
            description=(
                f"Endpoint {result.target.url} accepted "
                f"{result.success_count}/{result.total_sent} requests in a "
                f"rapid burst without enforcing a rate limit.  "
                f"Business-critical actions should restrict the number of "
                f"attempts per user/session to prevent abuse."
            ),
            severity=Severity.MEDIUM,
            module="WaaaghLogic",
            target=target,
            evidence=(
                f"Burst of {result.total_sent} {result.target.method} requests: "
                f"{result.success_count} succeeded, "
                f"{result.rate_limited_count} rate-limited (429/503), "
                f"{result.error_count} errors. "
                f"Status codes: {result.status_codes}"
            ),
            remediation=(
                "Implement server-side rate limiting on this endpoint.  "
                "Use a sliding-window or token-bucket algorithm, keyed by "
                "authenticated user or session.  Return HTTP 429 with a "
                "Retry-After header when the limit is exceeded."
            ),
            cwe=799,
            tags=["rate-limit", "business-logic", "abuse"],
        )
