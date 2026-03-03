"""
WaaaghLogic — Bulk operation abuse testing.

Mass delete/update/export, batch endpoint limits, resource exhaustion
via unbounded bulk operations.

CWE-770: Allocation of Resources Without Limits or Throttling
CWE-799: Improper Control of Interaction Frequency
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.bulk_operation_abuse")

# Bulk operation payload patterns
_BULK_DELETE_PAYLOADS: List[Dict[str, Any]] = [
    {"label": "Wildcard delete", "body": {"ids": ["*"]}},
    {"label": "Negative ID delete", "body": {"ids": [-1, -2, -3]}},
    {"label": "Zero ID delete", "body": {"ids": [0]}},
    {"label": "Large batch delete", "body": {"ids": list(range(1, 1001))}},
    {"label": "SQL-injection ID", "body": {"ids": ["1 OR 1=1"]}},
    {"label": "Empty array delete", "body": {"ids": []}},
]

_BULK_UPDATE_PAYLOADS: List[Dict[str, Any]] = [
    {
        "label": "Mass status update",
        "body": {"ids": list(range(1, 101)), "status": "deleted"},
    },
    {
        "label": "Wildcard update",
        "body": {"filter": {"id": {"$gt": 0}}, "update": {"status": "inactive"}},
    },
    {
        "label": "All records update",
        "body": {"where": "1=1", "set": {"active": False}},
    },
]

_BULK_EXPORT_PAYLOADS: List[Dict[str, Any]] = [
    {"label": "Export all (no filter)", "params": {}},
    {"label": "Export with huge limit", "params": {"limit": 999999, "offset": 0}},
    {"label": "Export all pages", "params": {"page": 1, "per_page": 999999}},
    {"label": "Export with wildcard filter", "params": {"filter": "*"}},
]


class BulkOperationTester:
    """
    Test endpoints for bulk operation abuse:
      1. Unbounded batch delete
      2. Unbounded batch update
      3. Mass data export (no pagination limits)
      4. Batch endpoint rate-limiting
      5. Resource exhaustion via large batches
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        max_safe_batch: int = 100,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._max_safe_batch = max_safe_batch

    async def test(self, target: Target) -> List[Finding]:
        """Run all bulk operation tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=15.0, retries=0)

        try:
            findings.extend(await self._test_bulk_delete(client, target))
            findings.extend(await self._test_bulk_update(client, target))
            findings.extend(await self._test_bulk_export(client, target))
            findings.extend(await self._test_batch_rate_limit(client, target))
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_bulk_delete(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test for unbounded batch delete operations."""
        findings: List[Finding] = []

        for payload in _BULK_DELETE_PAYLOADS:
            try:
                resp = await client.request(
                    "DELETE", target.url, json_body=payload["body"],
                )
                if resp.status_code in (200, 202, 204):
                    ids = payload["body"].get("ids", [])
                    if isinstance(ids, list) and (
                        len(ids) > self._max_safe_batch or ids == ["*"]
                    ):
                        findings.append(Finding(
                            title=f"Unbounded bulk delete accepted on {target.url}",
                            description=(
                                f"The endpoint accepted a bulk delete of "
                                f"{len(ids) if ids != ['*'] else 'wildcard (*)'} items. "
                                f"Unbounded batch deletions can cause data loss, "
                                f"service disruption, or denial of service."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Payload: {payload['label']}\n"
                                f"Status: {resp.status_code}\n"
                                f"Batch size: {len(ids)}"
                            ),
                            remediation=(
                                "Enforce maximum batch size limits. Require confirmation "
                                "for large batch operations. Implement soft-delete with "
                                "recovery period."
                            ),
                            cwe=770,
                            tags=["bulk-operation", "mass-delete", "waaaghlogic"],
                        ))
                        return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_bulk_update(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test for unbounded batch update operations."""
        findings: List[Finding] = []

        for payload in _BULK_UPDATE_PAYLOADS:
            try:
                resp = await client.request(
                    "PATCH", target.url, json_body=payload["body"],
                )
                if resp.status_code in (200, 202, 204):
                    findings.append(Finding(
                        title=f"Bulk update accepted: {payload['label']} on {target.url}",
                        description=(
                            f"The endpoint accepted a bulk update operation "
                            f"({payload['label']}). Unbounded batch updates can "
                            f"corrupt data en masse or be used for privilege "
                            f"escalation when combined with mass assignment."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"Payload: {payload['label']}\n"
                            f"Status: {resp.status_code}"
                        ),
                        remediation=(
                            "Enforce maximum batch sizes. Require explicit confirmation "
                            "for operations affecting many records. Log and alert on "
                            "bulk modifications."
                        ),
                        cwe=770,
                        tags=["bulk-operation", "mass-update", "waaaghlogic"],
                    ))
                    return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_bulk_export(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test for mass data export without pagination limits."""
        findings: List[Finding] = []

        for payload in _BULK_EXPORT_PAYLOADS:
            try:
                resp = await client.request(
                    "GET", target.url, params=payload["params"],
                )
                if resp.status_code in (200, 201):
                    body_size = len(resp.text)
                    # Large response suggests missing pagination limits
                    if body_size > 100_000:  # > 100KB
                        findings.append(Finding(
                            title=f"Mass export without limit on {target.url}",
                            description=(
                                f"A single request with {payload['label']} returned "
                                f"{body_size:,} bytes. Endpoints without pagination "
                                f"limits allow mass data exfiltration and can cause "
                                f"memory exhaustion."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Params: {payload['params']}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response size: {body_size:,} bytes"
                            ),
                            remediation=(
                                "Enforce maximum page sizes (e.g., 100 items). "
                                "Require pagination parameters. Implement server-side "
                                "caps regardless of client request."
                            ),
                            cwe=770,
                            tags=["bulk-operation", "mass-export", "data-exposure", "waaaghlogic"],
                        ))
                        return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_batch_rate_limit(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send rapid batch requests to check for rate-limiting."""
        findings: List[Finding] = []
        success_count = 0

        try:
            for i in range(10):
                body = {"ids": list(range(i * 10, (i + 1) * 10))}
                resp = await client.request(
                    target.method or "POST", target.url, json_body=body,
                )
                if resp.status_code == 429:
                    return findings  # rate-limiting present
                if resp.status_code in (200, 201, 202, 204):
                    success_count += 1
        except (httpx.HTTPError, OSError, ValueError):
            pass

        if success_count >= 10:
            findings.append(Finding(
                title=f"No rate-limiting on batch endpoint {target.url}",
                description=(
                    "Sent 10 rapid batch requests without triggering "
                    "rate-limiting. An attacker could abuse batch endpoints "
                    "for mass operations or resource exhaustion."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Success: {success_count}/10 rapid requests",
                remediation=(
                    "Implement rate-limiting on batch endpoints. "
                    "Track total items processed, not just request count."
                ),
                cwe=799,
                tags=["bulk-operation", "rate-limit", "waaaghlogic"],
            ))

        return findings
