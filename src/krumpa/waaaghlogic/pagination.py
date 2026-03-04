"""
WaaaghLogic — Pagination / rate limit tester.

Tests for:
- Pagination bypass (large page sizes, negative offsets)
- Rate limit exhaustion
- Missing pagination on list endpoints
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, List

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.pagination")


@dataclass
class PaginationResult:
    """Result of a pagination test."""
    has_pagination: bool
    max_page_size_accepted: int = 0
    total_items_exposed: int = 0
    rate_limited: bool = False


class PaginationTester(HttpClientMixin):
    """Test pagination controls and rate limit enforcement."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def test(self, target: Target) -> List[Finding]:
        """Test pagination and rate limits on a list endpoint."""
        if not self._client:
            return []

        findings: List[Finding] = []

        # Test large page sizes
        for size in [1000, 10000, 100000]:
            for param in ["limit", "page_size", "pageSize", "per_page", "count", "size"]:
                try:
                    sep = "&" if "?" in target.url else "?"
                    url = f"{target.url}{sep}{param}={size}"
                    resp = await self._client.request(method="GET", url=url)
                    if resp.status_code < 400:
                        body = resp.json() if hasattr(resp, 'json') else None
                        items = 0
                        if isinstance(body, list):
                            items = len(body)
                        elif isinstance(body, dict):
                            for key in ("data", "results", "items", "records"):
                                if isinstance(body.get(key), list):
                                    items = len(body[key])
                                    break

                        if items > 100:
                            findings.append(Finding(
                                title=f"Excessive data exposure via large page size ({param}={size})",
                                description=(
                                    f"Endpoint {target.url} accepted {param}={size} and returned "
                                    f"{items} items. Missing server-side pagination limits."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=f"param={param}, size={size}, items={items}",
                                remediation="Enforce maximum page size server-side (e.g., max 100 items per request).",
                                cwe=770,
                                tags=["pagination", "excessive-data", "api"],
                            ))
                            break
                except Exception:
                    pass

        # Test negative/zero offsets
        for param, val in [("offset", "-1"), ("page", "0"), ("page", "-1"), ("skip", "-1")]:
            try:
                sep = "&" if "?" in target.url else "?"
                url = f"{target.url}{sep}{param}={val}"
                resp = await self._client.request(method="GET", url=url)
                if resp.status_code < 400:
                    findings.append(Finding(
                        title=f"Invalid pagination parameter accepted ({param}={val})",
                        description=f"Endpoint accepted {param}={val} without validation.",
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"param={param}, value={val}, status={resp.status_code}",
                        remediation="Validate pagination parameters: offset >= 0, page >= 1.",
                        cwe=20,
                        tags=["pagination", "input-validation"],
                    ))
            except Exception:
                pass

        # Test rate limiting
        rate_limited = False
        start = time.monotonic()
        for _i in range(50):
            try:
                resp = await self._client.request(method="GET", url=target.url)
                if resp.status_code == 429:
                    rate_limited = True
                    break
            except Exception:
                break
        elapsed = time.monotonic() - start

        if not rate_limited and elapsed < 5.0:
            findings.append(Finding(
                title="No rate limiting detected on list endpoint",
                description=(
                    f"50 requests to {target.url} completed in {elapsed:.1f}s "
                    f"without rate limiting."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=f"requests=50, elapsed={elapsed:.1f}s, rate_limited=false",
                remediation="Implement rate limiting on API endpoints.",
                cwe=799,
                tags=["rate-limit", "api"],
            ))

        return findings
