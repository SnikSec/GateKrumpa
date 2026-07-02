"""
WaaaghLogic — Horizontal & Vertical Privilege Escalation tester.

Tests for:
- Horizontal: access other users' resources by swapping IDs
- Vertical: access admin-only endpoints with regular user tokens
- IDOR: enumerate and access sequential/predictable object IDs
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.privilege_escalation")


@dataclass
class PrivEscResult:
    """Result of a single privilege escalation test."""
    test_type: str  # "horizontal", "vertical", "idor"
    target: Target
    original_status: int
    escalated_status: int
    was_blocked: bool
    evidence: str = ""


# URL patterns that hint at user-specific resources
_ID_PATTERNS = [
    re.compile(r"/users?/(\d+)"),
    re.compile(r"/accounts?/(\d+)"),
    re.compile(r"/profiles?/(\d+)"),
    re.compile(r"/orders?/(\d+)"),
    re.compile(r"/[a-z]+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    re.compile(r"/[a-z]+/(\d{1,10})(?:/|$|\?)"),
]

# Endpoints that typically require admin privileges
_ADMIN_HINTS = {
    "/admin", "/dashboard", "/manage", "/settings", "/config",
    "/users", "/roles", "/permissions", "/audit", "/logs",
    "/system", "/internal", "/debug", "/metrics", "/health",
}


class PrivilegeEscalationTester(HttpClientMixin):
    """
    Test for horizontal and vertical privilege escalation vulnerabilities.
    """

    def __init__(
        self,
        http_client: Any = None,
        *,
        test_ids: Optional[List[str]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = False
        self._test_ids = test_ids or ["1", "2", "999", "0"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test_horizontal(
        self,
        target: Target,
        *,
        user_token: Optional[str] = None,
        other_user_id: str = "999999",
    ) -> List[Finding]:
        """
        Test horizontal privilege escalation by replacing IDs in the URL.
        """
        if not self._client:
            return []

        findings: List[Finding] = []
        original_url = target.url

        # Find ID segments in the URL
        for pattern in _ID_PATTERNS:
            match = pattern.search(original_url)
            if not match:
                continue

            original_id = match.group(1)
            # Try replacing with another user's ID
            for other_id in [other_user_id] + self._test_ids:
                if other_id == original_id:
                    continue

                modified_url = original_url[:match.start(1)] + other_id + original_url[match.end(1):]
                headers = {}
                if user_token:
                    headers["Authorization"] = f"Bearer {user_token}"

                try:
                    resp = await self._client.request(
                        method=target.method or "GET",
                        url=modified_url,
                        headers=headers,
                    )

                    if resp.status_code < 400:
                        findings.append(Finding(
                            title=f"Horizontal privilege escalation: IDOR on {target.url}",
                            description=(
                                f"Replacing ID '{original_id}' with '{other_id}' "
                                f"returned HTTP {resp.status_code}. "
                                f"This may allow accessing another user's data."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=f"original_id={original_id}, other_id={other_id}, status={resp.status_code}",
                            remediation=(
                                "Implement proper authorization checks. Verify that the "
                                "authenticated user owns or has access to the requested resource."
                            ),
                            cwe=639,  # Authorization Bypass Through User-Controlled Key
                            tags=["idor", "horizontal-privesc", "authorization"],
                        ))
                        break  # one confirmation suffices

                except Exception as exc:
                    logger.debug("Error testing horizontal privesc: %s", exc)

        return findings

    async def test_vertical(
        self,
        target: Target,
        *,
        regular_token: Optional[str] = None,
        admin_endpoints: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Test vertical privilege escalation by accessing admin endpoints
        with a regular user's token.
        """
        if not self._client:
            return []

        findings: List[Finding] = []
        endpoints = admin_endpoints or self._detect_admin_endpoints(target)

        headers = {}
        if regular_token:
            headers["Authorization"] = f"Bearer {regular_token}"

        for endpoint in endpoints:
            try:
                resp = await self._client.request(
                    method="GET",
                    url=endpoint,
                    headers=headers,
                )

                if resp.status_code < 400:
                    findings.append(Finding(
                        title="Vertical privilege escalation: admin endpoint accessible",
                        description=(
                            f"Admin endpoint {endpoint} returned HTTP {resp.status_code} "
                            f"with a regular user token. This indicates missing or "
                            f"insufficient role-based access control."
                        ),
                        severity=Severity.CRITICAL,
                        target=Target(url=endpoint, method="GET"),
                        evidence=f"endpoint={endpoint}, status={resp.status_code}",
                        remediation=(
                            "Enforce role-based access control (RBAC). Admin endpoints "
                            "must verify the user has the required role before processing."
                        ),
                        cwe=269,  # Improper Privilege Management
                        tags=["vertical-privesc", "authorization", "rbac"],
                    ))

            except Exception as exc:
                logger.debug("Error testing vertical privesc on %s: %s", endpoint, exc)

        return findings

    async def test_idor(
        self,
        target: Target,
        *,
        sequential_range: int = 5,
    ) -> List[Finding]:
        """
        Test for predictable/sequential ID enumeration.
        """
        if not self._client:
            return []

        findings: List[Finding] = []

        for pattern in _ID_PATTERNS:
            match = pattern.search(target.url)
            if not match:
                continue

            original_id = match.group(1)
            try:
                base_id = int(original_id)
            except ValueError:
                continue

            accessible_count = 0
            tested_count = 0

            for offset in range(1, sequential_range + 1):
                for test_id in [str(base_id + offset), str(base_id - offset)]:
                    if test_id == original_id or int(test_id) < 0:
                        continue

                    modified_url = target.url[:match.start(1)] + test_id + target.url[match.end(1):]
                    tested_count += 1

                    try:
                        resp = await self._client.request(
                            method=target.method or "GET",
                            url=modified_url,
                        )
                        if resp.status_code < 400:
                            accessible_count += 1
                    except Exception:
                        pass

            if accessible_count > sequential_range // 2 and tested_count > 0:
                findings.append(Finding(
                    title=f"IDOR: sequential ID enumeration on {target.url}",
                    description=(
                        f"Successfully accessed {accessible_count}/{tested_count} "
                        f"sequential IDs near '{original_id}'. Objects use "
                        f"predictable sequential identifiers."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"original_id={original_id}, accessible={accessible_count}/{tested_count}",
                    remediation=(
                        "Use UUIDs or other non-sequential identifiers. "
                        "Implement authorization checks on every resource access."
                    ),
                    cwe=639,
                    tags=["idor", "enumeration"],
                ))
            break  # test only the first matching pattern

        return findings

    # ------------------------------------------------------------------
    # Offline analysis
    # ------------------------------------------------------------------

    def analyze_endpoints(
        self,
        targets: List[Target],
    ) -> List[Dict[str, Any]]:
        """
        Analyze endpoints for potential privilege escalation without making requests.
        Returns a list of test recommendations.
        """
        recommendations: List[Dict[str, Any]] = []

        for target in targets:
            url = target.url.lower()

            # Check for ID patterns
            for pattern in _ID_PATTERNS:
                if pattern.search(target.url):
                    recommendations.append({
                        "target": target.url,
                        "test": "horizontal_privesc",
                        "reason": "URL contains user-controllable ID",
                        "priority": "high",
                    })
                    break

            # Check for admin-like endpoints
            for hint in _ADMIN_HINTS:
                if hint in url:
                    recommendations.append({
                        "target": target.url,
                        "test": "vertical_privesc",
                        "reason": f"URL matches admin pattern '{hint}'",
                        "priority": "critical",
                    })
                    break

        return recommendations

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_admin_endpoints(target: Target) -> List[str]:
        """Derive potential admin endpoints from a target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints: List[str] = []
        for hint in sorted(_ADMIN_HINTS):
            endpoints.append(f"{base}{hint}")

        return endpoints
