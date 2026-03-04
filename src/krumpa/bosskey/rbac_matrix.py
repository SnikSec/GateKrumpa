"""
BossKey — RBAC matrix builder.

Builds a role-based access control matrix from scan results and
identifies permission gaps.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.rbac_matrix")


@dataclass
class RbacEntry:
    """A single RBAC test result."""
    endpoint: str
    method: str
    role: str
    status_code: int
    allowed: bool


@dataclass
class RbacMatrix:
    """Complete RBAC matrix for an API."""
    roles: List[str]
    endpoints: List[str]
    entries: List[RbacEntry] = field(default_factory=list)

    def get_allowed(self, role: str) -> List[str]:
        return [e.endpoint for e in self.entries if e.role == role and e.allowed]

    def get_denied(self, role: str) -> List[str]:
        return [e.endpoint for e in self.entries if e.role == role and not e.allowed]

    def find_gaps(self) -> List[Dict[str, Any]]:
        """Find endpoints accessible to lower-privilege roles."""
        gaps: List[Dict[str, Any]] = []
        role_order = {r: i for i, r in enumerate(self.roles)}

        for endpoint in self.endpoints:
            min_role_idx = len(self.roles)
            for e in self.entries:
                if e.endpoint == endpoint and e.allowed:
                    idx = role_order.get(e.role, len(self.roles))
                    if idx < min_role_idx:
                        min_role_idx = idx

            if min_role_idx < len(self.roles) - 1:
                # Check if lower-privilege roles also have access
                for e in self.entries:
                    if e.endpoint == endpoint and e.allowed:
                        idx = role_order.get(e.role, 0)
                        if idx < min_role_idx:
                            gaps.append({
                                "endpoint": endpoint,
                                "role": e.role,
                                "expected_min_role": self.roles[min_role_idx],
                            })

        return gaps


class RbacMatrixBuilder(HttpClientMixin):
    """Build and analyze RBAC matrices."""

    def __init__(
        self,
        http_client: Any = None,
        *,
        roles: Optional[List[str]] = None,
        role_tokens: Optional[Dict[str, str]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = False
        self._roles = roles or ["anonymous", "user", "admin"]
        self._role_tokens = role_tokens or {}

    async def build_matrix(
        self,
        endpoints: List[Target],
    ) -> RbacMatrix:
        """Build an RBAC matrix by testing each endpoint with each role."""
        matrix = RbacMatrix(
            roles=self._roles,
            endpoints=[f"{t.method} {t.url}" for t in endpoints],
        )

        if not self._client:
            return matrix

        for target in endpoints:
            for role in self._roles:
                headers = {}
                token = self._role_tokens.get(role)
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                try:
                    resp = await self._client.request(
                        method=target.method or "GET",
                        url=target.url,
                        headers=headers,
                    )
                    allowed = resp.status_code < 400
                    matrix.entries.append(RbacEntry(
                        endpoint=f"{target.method} {target.url}",
                        method=target.method,
                        role=role,
                        status_code=resp.status_code,
                        allowed=allowed,
                    ))
                except Exception as exc:
                    logger.debug("RBAC test error: %s", exc)

        return matrix

    async def test_and_report(
        self,
        endpoints: List[Target],
    ) -> List[Finding]:
        """Build matrix and return findings for permission gaps."""
        matrix = await self.build_matrix(endpoints)
        findings: List[Finding] = []

        # Check anonymous access to authenticated endpoints
        for entry in matrix.entries:
            if entry.role == "anonymous" and entry.allowed:
                findings.append(Finding(
                    title=f"Unauthenticated access: {entry.endpoint}",
                    description=f"Endpoint {entry.endpoint} is accessible without authentication (status {entry.status_code}).",
                    severity=Severity.HIGH,
                    target=Target(url=entry.endpoint.split(" ", 1)[-1], method=entry.method),
                    evidence=f"role=anonymous, status={entry.status_code}",
                    remediation="Require authentication for this endpoint.",
                    cwe=306,
                    tags=["rbac", "authentication", "unauthenticated-access"],
                ))

        # Check gaps
        gaps = matrix.find_gaps()
        for gap in gaps:
            findings.append(Finding(
                title=f"RBAC gap: {gap['role']} can access {gap['endpoint']}",
                description=(
                    f"Role '{gap['role']}' has access to {gap['endpoint']} "
                    f"but minimum expected role is '{gap['expected_min_role']}'."
                ),
                severity=Severity.MEDIUM,
                target=Target(url=gap["endpoint"].split(" ", 1)[-1]),
                evidence=f"role={gap['role']}, expected={gap['expected_min_role']}",
                remediation="Review and tighten RBAC policies.",
                cwe=269,
                tags=["rbac", "authorization", "privilege-escalation"],
            ))

        return findings

    def format_matrix_markdown(self, matrix: RbacMatrix) -> str:
        """Format RBAC matrix as a markdown table."""
        lines = [f"| Endpoint | {' | '.join(matrix.roles)} |"]
        lines.append(f"|{'---|' * (len(matrix.roles) + 1)}")

        for endpoint in matrix.endpoints:
            row = [endpoint]
            for role in matrix.roles:
                entry = next(
                    (e for e in matrix.entries if e.endpoint == endpoint and e.role == role),
                    None,
                )
                if entry:
                    row.append("✅" if entry.allowed else "❌")
                else:
                    row.append("?")
            lines.append(f"| {' | '.join(row)} |")

        return "\n".join(lines)
