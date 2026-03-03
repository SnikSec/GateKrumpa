"""
OpenKrump — GraphQL schema analysis.

Analyses GraphQL introspection results for security issues:
- Introspection enabled in production
- Overly permissive queries (no depth/complexity limits)
- Sensitive field exposure
- Missing authentication on mutations
- Batching attack surface
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.graphql")


# Fields that are sensitive and should not be publicly queryable
_SENSITIVE_FIELDS: Set[str] = {
    "password", "passwordHash", "password_hash", "secret", "token",
    "apiKey", "api_key", "ssn", "socialSecurityNumber",
    "creditCard", "credit_card", "cardNumber", "card_number",
    "cvv", "pin", "privateKey", "private_key",
}

# Mutations that should always require authentication
_AUTH_REQUIRED_MUTATIONS: Set[str] = {
    "deleteUser", "delete_user", "updateRole", "update_role",
    "createAdmin", "create_admin", "resetPassword", "reset_password",
    "transferFunds", "transfer_funds", "elevatePrivileges",
}

_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}"""


@dataclass
class GraphqlField:
    """A field from the GraphQL schema."""
    name: str
    type_name: str = ""
    parent_type: str = ""
    args: List[str] = field(default_factory=list)


@dataclass
class GraphqlType:
    """A type from the GraphQL schema."""
    name: str
    kind: str
    fields: List[GraphqlField] = field(default_factory=list)


class GraphqlAnalyzer:
    """
    Analyze GraphQL schemas for security misconfigurations.
    """

    def __init__(
        self,
        http_client: Any = None,
    ) -> None:
        self._client = http_client
        self._owns_client = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Full GraphQL security analysis via introspection."""
        findings: List[Finding] = []

        schema = await self._introspect(target)
        if schema is None:
            # Introspection disabled — this is actually good security practice
            return findings

        # Introspection is enabled — this is a finding in production
        findings.append(Finding(
            title="GraphQL introspection is enabled",
            description=(
                f"GraphQL introspection is enabled at {target.url}. "
                f"This exposes the entire schema to attackers."
            ),
            severity=Severity.MEDIUM,
            target=target,
            evidence="Introspection query returned full schema",
            remediation="Disable introspection in production environments.",
            cwe=200,  # Exposure of Sensitive Information
            tags=["graphql", "introspection", "information-disclosure"],
        ))

        # Parse the schema
        types = self._parse_schema(schema)

        # Analyze for issues
        findings.extend(self._check_sensitive_fields(types, target))
        findings.extend(self._check_depth_complexity(types, target))
        findings.extend(self._check_mutations(types, target))
        findings.extend(await self._check_batching(target))

        return findings

    def analyze_schema(
        self,
        schema: Dict[str, Any],
        target: Optional[Target] = None,
    ) -> List[Finding]:
        """Analyse a pre-fetched schema (offline)."""
        t = target or Target(url="graphql://unknown")
        types = self._parse_schema(schema)
        findings: List[Finding] = []
        findings.extend(self._check_sensitive_fields(types, t))
        findings.extend(self._check_depth_complexity(types, t))
        findings.extend(self._check_mutations(types, t))
        return findings

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    async def _introspect(self, target: Target) -> Optional[Dict[str, Any]]:
        """Attempt GraphQL introspection."""
        if not self._client:
            return None

        try:
            resp = await self._client.request(
                method="POST",
                url=target.url,
                json={"query": _INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    return data["data"]["__schema"]
        except Exception as exc:
            logger.debug("Introspection failed: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Schema parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_schema(schema: Dict[str, Any]) -> List[GraphqlType]:
        """Parse introspection result into structured types."""
        types: List[GraphqlType] = []

        for type_def in schema.get("types", []):
            name = type_def.get("name", "")
            if name.startswith("__"):
                continue  # skip introspection types

            gql_type = GraphqlType(
                name=name,
                kind=type_def.get("kind", ""),
            )

            for field_def in (type_def.get("fields") or []):
                field_type = field_def.get("type", {})
                type_name = (
                    field_type.get("name")
                    or (field_type.get("ofType", {}) or {}).get("name", "")
                )
                gql_type.fields.append(GraphqlField(
                    name=field_def["name"],
                    type_name=type_name or "",
                    parent_type=name,
                    args=[a["name"] for a in (field_def.get("args") or [])],
                ))

            types.append(gql_type)

        return types

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_sensitive_fields(
        types: List[GraphqlType], target: Target,
    ) -> List[Finding]:
        """Check for sensitive fields exposed in the schema."""
        findings: List[Finding] = []
        exposed: List[str] = []

        for gql_type in types:
            for f in gql_type.fields:
                if f.name.lower() in {s.lower() for s in _SENSITIVE_FIELDS}:
                    exposed.append(f"{gql_type.name}.{f.name}")

        if exposed:
            findings.append(Finding(
                title=f"GraphQL: {len(exposed)} sensitive fields exposed",
                description=(
                    f"The GraphQL schema exposes potentially sensitive fields: "
                    f"{', '.join(exposed[:10])}"
                    + (f" and {len(exposed) - 10} more" if len(exposed) > 10 else "")
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(exposed),
                remediation=(
                    "Remove sensitive fields from the GraphQL schema or restrict "
                    "access with field-level authorization directives."
                ),
                cwe=200,
                tags=["graphql", "sensitive-data", "information-disclosure"],
            ))

        return findings

    @staticmethod
    def _check_depth_complexity(
        types: List[GraphqlType], target: Target,
    ) -> List[Finding]:
        """Check for recursive types that enable deep query attacks."""
        findings: List[Finding] = []
        recursive_types: List[str] = []

        type_names = {t.name for t in types}
        for gql_type in types:
            for f in gql_type.fields:
                if f.type_name == gql_type.name:
                    recursive_types.append(f"{gql_type.name}.{f.name}")
                elif f.type_name in type_names:
                    # Check if the referenced type references back
                    ref_type = next((t for t in types if t.name == f.type_name), None)
                    if ref_type:
                        for ref_field in ref_type.fields:
                            if ref_field.type_name == gql_type.name:
                                recursive_types.append(
                                    f"{gql_type.name}.{f.name} <-> {f.type_name}.{ref_field.name}"
                                )

        if recursive_types:
            findings.append(Finding(
                title="GraphQL: recursive types enable depth attacks",
                description=(
                    f"Schema contains {len(recursive_types)} recursive type relationships "
                    f"that could be exploited for denial-of-service via deeply nested queries. "
                    f"Examples: {', '.join(recursive_types[:5])}"
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(recursive_types),
                remediation=(
                    "Implement query depth limiting, complexity analysis, and "
                    "query cost budgets. Libraries like graphql-depth-limit or "
                    "graphql-query-complexity can help."
                ),
                cwe=400,  # Uncontrolled Resource Consumption
                tags=["graphql", "dos", "depth-limit"],
            ))

        return findings

    @staticmethod
    def _check_mutations(
        types: List[GraphqlType], target: Target,
    ) -> List[Finding]:
        """Check mutations for security-sensitive operations."""
        findings: List[Finding] = []
        risky_mutations: List[str] = []

        for gql_type in types:
            if gql_type.name.lower() in ("mutation", "mutationtype"):
                for f in gql_type.fields:
                    if f.name.lower() in {m.lower() for m in _AUTH_REQUIRED_MUTATIONS}:
                        risky_mutations.append(f.name)

        if risky_mutations:
            findings.append(Finding(
                title=f"GraphQL: {len(risky_mutations)} sensitive mutations exposed",
                description=(
                    f"The schema exposes sensitive mutations that should require "
                    f"strong authentication: {', '.join(risky_mutations)}"
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(risky_mutations),
                remediation=(
                    "Ensure all sensitive mutations require authentication and "
                    "proper authorization. Use middleware or directives to enforce."
                ),
                cwe=306,  # Missing Authentication for Critical Function
                tags=["graphql", "mutations", "authentication"],
            ))

        return findings

    async def _check_batching(self, target: Target) -> List[Finding]:
        """Check if array-based query batching is allowed."""
        if not self._client:
            return []

        try:
            # Send a batched query
            batch = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            resp = await self._client.request(
                method="POST",
                url=target.url,
                json_body=batch,
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == 2:
                    return [Finding(
                        title="GraphQL: query batching enabled",
                        description=(
                            f"GraphQL endpoint at {target.url} accepts batched queries. "
                            f"This can be abused for brute-force attacks and "
                            f"rate-limit bypass."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence="Batched query returned array of 2 results",
                        remediation=(
                            "Disable query batching or implement per-query "
                            "rate limiting and complexity analysis."
                        ),
                        cwe=799,  # Improper Control of Interaction Frequency
                        tags=["graphql", "batching", "rate-limit"],
                    )]

        except Exception as exc:
            logger.debug("Batching check error: %s", exc)

        return []
