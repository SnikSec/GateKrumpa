"""
WaaaghLogic — idempotency and race-condition checker.

Tests state-changing endpoints for:
  - Duplicate submission acceptance (missing idempotency controls)
  - Concurrent request race conditions (TOCTOU)
  - Response consistency under rapid-fire repetition
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.idempotency")


# ------------------------------------------------------------------
# Data
# ------------------------------------------------------------------

@dataclass
class _RaceResult:
    """Aggregated outcome of concurrent requests."""
    total: int
    succeeded: int
    status_codes: List[int]
    bodies: List[str]


# ------------------------------------------------------------------
# IdempotencyChecker
# ------------------------------------------------------------------

class IdempotencyChecker:
    """
    Test endpoints for idempotency and race-condition vulnerabilities.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    concurrency:
        Number of simultaneous requests for race-condition tests.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        concurrency: int = 5,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.concurrency = concurrency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(
        self,
        url: str,
        target: Target,
        *,
        method: str = "POST",
        body: Optional[Dict[str, Any]] = None,
        expected_status: int = 200,
    ) -> List[Finding]:
        """
        Run idempotency and race-condition tests on *url*.
        """
        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            findings: List[Finding] = []
            findings.extend(
                await self._test_duplicate(client, url, target, method, body, expected_status)
            )
            findings.extend(
                await self._test_race(client, url, target, method, body, expected_status)
            )
            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Duplicate submission
    # ------------------------------------------------------------------

    async def _test_duplicate(
        self,
        client: HttpClient,
        url: str,
        target: Target,
        method: str,
        body: Optional[Dict[str, Any]],
        expected_status: int,
    ) -> List[Finding]:
        """Send the same request twice sequentially."""
        r1 = await self._send(client, method, url, body)
        r2 = await self._send(client, method, url, body)

        if r1 and r2 and r1["status"] == expected_status and r2["status"] == expected_status:
            return [Finding(
                title=f"Duplicate submission accepted on {method} {url}",
                description=(
                    f"Two identical {method} requests to {url} both returned "
                    f"status {expected_status}. The endpoint may lack idempotency "
                    "controls, allowing duplicate transactions."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Request 1 → {r1['status']}, Request 2 → {r2['status']}",
                remediation=(
                    "Implement idempotency keys or server-side duplicate detection "
                    "for state-changing operations."
                ),
                cwe=841,
                tags=["business-logic", "idempotency", "duplicate"],
            )]

        return []

    # ------------------------------------------------------------------
    # Race condition
    # ------------------------------------------------------------------

    async def _test_race(
        self,
        client: HttpClient,
        url: str,
        target: Target,
        method: str,
        body: Optional[Dict[str, Any]],
        expected_status: int,
    ) -> List[Finding]:
        """Fire concurrent requests and check how many succeed."""
        tasks = [
            self._send(client, method, url, body)
            for _ in range(self.concurrency)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in results if r is not None and not isinstance(r, BaseException)]
        succeeded = sum(1 for r in valid if r["status"] == expected_status)

        race_result = _RaceResult(
            total=len(valid),
            succeeded=succeeded,
            status_codes=[r["status"] for r in valid],
            bodies=[r["body"] for r in valid],
        )

        findings: List[Finding] = []

        # Multiple successes from concurrent requests → possible race
        if race_result.succeeded > 1:
            findings.append(Finding(
                title=f"Race condition: {race_result.succeeded}/{race_result.total} concurrent requests succeeded",
                description=(
                    f"Sent {self.concurrency} concurrent {method} requests to {url}. "
                    f"{race_result.succeeded} returned status {expected_status}. "
                    "This indicates a potential TOCTOU race condition."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Statuses: {race_result.status_codes}",
                remediation=(
                    "Use database-level locks, optimistic concurrency control, or "
                    "serialised queues for state-changing operations."
                ),
                cwe=362,
                tags=["business-logic", "race-condition", "toctou"],
            ))

        # Inconsistent responses → state leak
        unique_bodies = set(race_result.bodies)
        if len(unique_bodies) > 1 and race_result.succeeded > 1:
            findings.append(Finding(
                title=f"Inconsistent responses under concurrency on {url}",
                description=(
                    f"Concurrent requests to {url} produced {len(unique_bodies)} "
                    "distinct response bodies, suggesting inconsistent server-side state."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Ensure atomic state transitions for concurrent requests.",
                cwe=362,
                tags=["business-logic", "race-condition", "inconsistency"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _send(
        client: HttpClient,
        method: str,
        url: str,
        body: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = await client.request(method, url, json_body=body)
            return {"status": resp.status_code, "body": resp.text}
        except (httpx.HTTPError, OSError):
            logger.debug("Request to %s failed", url)
            return None
