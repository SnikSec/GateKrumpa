"""
WaaaghLogic — GraphQL-specific logic testing.

Batching abuse, depth bombs, alias abuse, field-level authorization,
introspection exposure, and query complexity attacks.

CWE-770: Allocation of Resources Without Limits or Throttling
CWE-285: Improper Authorization
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.graphql_logic")


def _depth_bomb_query(depth: int) -> str:
    """Build a deeply nested GraphQL query."""
    query = "{ " + " { ".join([f"a{i}" for i in range(depth)])
    query += " id " + " } " * depth
    return query


def _alias_abuse_query(count: int) -> str:
    """Build a query with many aliased fields."""
    aliases = " ".join([f"a{i}: __typename" for i in range(count)])
    return f"{{ {aliases} }}"


def _batch_mutation_query(count: int) -> str:
    """Build a batched mutation query."""
    mutations = " ".join([
        f'm{i}: createItem(input: {{name: "test{i}"}}) {{ id }}'
        for i in range(count)
    ])
    return f"mutation {{ {mutations} }}"


# Introspection queries
_INTROSPECTION_QUERIES = [
    {"label": "Full introspection", "query": "{ __schema { types { name fields { name } } } }"},
    {"label": "__type query", "query": '{ __type(name: "User") { fields { name type { name } } } }'},
    {"label": "Mutation list", "query": "{ __schema { mutationType { fields { name } } } }"},
    {"label": "Subscription list", "query": "{ __schema { subscriptionType { fields { name } } } }"},
]

# Directive injection payloads
_DIRECTIVE_PAYLOADS = [
    {"label": "Skip directive", "query": '{ users { id name @skip(if: false) email @skip(if: false) password @skip(if: false) } }'},
    {"label": "Include all", "query": '{ users { id name @include(if: true) secretField @include(if: true) } }'},
    {"label": "Deprecated fields", "query": '{ users { id name deprecatedField } }'},
]


class GraphqlLogicTester:
    """
    Test GraphQL endpoints for:
      1. Query depth bombs (deeply nested queries)
      2. Alias abuse (hundreds of aliased fields)
      3. Batch mutation abuse (hundreds of mutations in one request)
      4. Introspection exposure in production
      5. Field-level authorization bypass
      6. Query complexity / cost limits
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        max_depth: int = 50,
        max_aliases: int = 500,
        max_batch: int = 100,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._max_depth = max_depth
        self._max_aliases = max_aliases
        self._max_batch = max_batch

    async def test(self, target: Target) -> List[Finding]:
        """Run all GraphQL logic tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=15.0, retries=0)

        try:
            findings.extend(await self._test_depth_bomb(client, target))
            findings.extend(await self._test_alias_abuse(client, target))
            findings.extend(await self._test_batch_mutations(client, target))
            findings.extend(await self._test_introspection(client, target))
            findings.extend(await self._test_field_authorization(client, target))
            findings.extend(await self._test_query_complexity(client, target))
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_depth_bomb(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send deeply nested queries to test depth limits."""
        findings: List[Finding] = []

        for depth in [10, 25, 50, 100]:
            if depth > self._max_depth:
                break
            query = _depth_bomb_query(depth)
            try:
                resp = await client.request(
                    "POST", target.url,
                    json_body={"query": query},
                )
                if resp.status_code in (200, 201):
                    body = resp.text
                    # If no depth-limit error, the query was accepted
                    if "error" not in body.lower() or "depth" not in body.lower():
                        if depth >= 25:
                            findings.append(Finding(
                                title=f"GraphQL depth bomb accepted (depth={depth}) on {target.url}",
                                description=(
                                    f"A query nested to depth {depth} was accepted "
                                    f"without rejection. Deeply nested queries can "
                                    f"cause exponential resource usage and DoS."
                                ),
                                severity=Severity.HIGH if depth >= 50 else Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Depth: {depth}\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Response snippet: {body[:200]}"
                                ),
                                remediation=(
                                    "Implement query depth limiting (recommended max: 10-15). "
                                    "Use a query complexity analysis library. "
                                    "Reject queries exceeding depth thresholds."
                                ),
                                cwe=770,
                                tags=["graphql", "depth-bomb", "dos", "waaaghlogic"],
                            ))
                            return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_alias_abuse(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send queries with hundreds of aliases."""
        findings: List[Finding] = []

        for count in [50, 200, 500]:
            if count > self._max_aliases:
                break
            query = _alias_abuse_query(count)
            try:
                resp = await client.request(
                    "POST", target.url,
                    json_body={"query": query},
                )
                if resp.status_code in (200, 201):
                    body = resp.text
                    if "error" not in body.lower():
                        if count >= 200:
                            findings.append(Finding(
                                title=f"GraphQL alias abuse accepted ({count} aliases) on {target.url}",
                                description=(
                                    f"A query with {count} aliased fields was accepted. "
                                    f"Alias abuse amplifies a single query into many "
                                    f"resolver calls, enabling DoS and data scraping."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Aliases: {count}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Limit the number of aliases per query. "
                                    "Implement query cost analysis that counts aliases. "
                                    "Use persisted queries in production."
                                ),
                                cwe=770,
                                tags=["graphql", "alias-abuse", "dos", "waaaghlogic"],
                            ))
                            return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_batch_mutations(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send batched mutations to test batch limits."""
        findings: List[Finding] = []

        # Test array-based batching
        for count in [10, 50, 100]:
            if count > self._max_batch:
                break
            batch = [
                {"query": f'mutation {{ createItem(input: {{name: "t{i}"}}) {{ id }} }}'}
                for i in range(count)
            ]
            try:
                resp = await client.request(
                    "POST", target.url,
                    json_body=batch,
                )
                if resp.status_code in (200, 201):
                    body = resp.text
                    if "error" not in body.lower() and count >= 50:
                        findings.append(Finding(
                            title=f"GraphQL batch abuse accepted ({count} ops) on {target.url}",
                            description=(
                                f"A batch of {count} mutations was accepted. "
                                f"Unbounded batching enables mass operations, "
                                f"rate-limit bypass, and brute-force attacks."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Batch size: {count}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Limit batch size (e.g., max 10 operations per request). "
                                "Implement query cost for batched operations. "
                                "Consider disabling batching in production."
                            ),
                            cwe=770,
                            tags=["graphql", "batch-abuse", "waaaghlogic"],
                        ))
                        return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_introspection(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Check if introspection is enabled in production."""
        findings: List[Finding] = []

        for spec in _INTROSPECTION_QUERIES:
            try:
                resp = await client.request(
                    "POST", target.url,
                    json_body={"query": spec["query"]},
                )
                if resp.status_code in (200, 201):
                    try:
                        data = json.loads(resp.text)
                        if "data" in data and data["data"]:
                            schema_data = data["data"]
                            if "__schema" in schema_data or "__type" in schema_data:
                                findings.append(Finding(
                                    title=f"GraphQL introspection enabled on {target.url}",
                                    description=(
                                        f"Introspection query ({spec['label']}) returned "
                                        f"schema information. Introspection in production "
                                        f"exposes the entire API surface to attackers."
                                    ),
                                    severity=Severity.MEDIUM,
                                    target=target,
                                    evidence=(
                                        f"Query: {spec['label']}\n"
                                        f"Status: {resp.status_code}\n"
                                        f"Schema data returned: Yes"
                                    ),
                                    remediation=(
                                        "Disable introspection in production. "
                                        "Use allowlists / persisted queries. "
                                        "If introspection is needed, restrict to authenticated admins."
                                    ),
                                    cwe=200,
                                    tags=["graphql", "introspection", "information-disclosure", "waaaghlogic"],
                                ))
                                return findings
                    except json.JSONDecodeError:
                        pass
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_field_authorization(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test field-level authorization by requesting sensitive fields."""
        findings: List[Finding] = []
        sensitive_fields = [
            "password", "passwordHash", "secret", "apiKey", "token",
            "ssn", "creditCard", "internalId", "privateKey",
        ]

        for field_name in sensitive_fields:
            query = f"{{ users {{ id name {field_name} }} }}"
            try:
                resp = await client.request(
                    "POST", target.url,
                    json_body={"query": query},
                )
                if resp.status_code in (200, 201):
                    try:
                        data = json.loads(resp.text)
                        if "data" in data and data["data"]:
                            users = data["data"].get("users", [])
                            if isinstance(users, list) and users:
                                for user in users[:1]:
                                    if isinstance(user, dict) and field_name in user:
                                        findings.append(Finding(
                                            title=f"Sensitive GraphQL field exposed: {field_name} on {target.url}",
                                            description=(
                                                f"The field '{field_name}' is queryable "
                                                f"and returns data. Sensitive fields should "
                                                f"not be exposed via the GraphQL schema or "
                                                f"should require elevated authorization."
                                            ),
                                            severity=Severity.HIGH,
                                            target=target,
                                            evidence=(
                                                f"Field: {field_name}\n"
                                                f"Query: {query}\n"
                                                f"Status: {resp.status_code}"
                                            ),
                                            remediation=(
                                                "Remove sensitive fields from the GraphQL schema. "
                                                "Implement field-level authorization directives. "
                                                "Use schema stitching to separate public/private schemas."
                                            ),
                                            cwe=285,
                                            tags=["graphql", "field-authorization", "data-exposure", "waaaghlogic"],
                                        ))
                                        return findings
                    except json.JSONDecodeError:
                        pass
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_query_complexity(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send a complex query to test cost analysis / complexity limits."""
        findings: List[Finding] = []

        # Combine depth + aliases + connections
        complex_query = """
        {
            users(first: 100) {
                id name email
                posts(first: 100) {
                    id title
                    comments(first: 100) {
                        id body
                        author { id name }
                    }
                }
                followers(first: 100) {
                    id name
                    posts(first: 100) { id title }
                }
            }
        }
        """
        try:
            resp = await client.request(
                "POST", target.url,
                json_body={"query": complex_query},
            )
            if resp.status_code in (200, 201):
                body = resp.text.lower()
                if "complexity" not in body and "cost" not in body:
                    findings.append(Finding(
                        title=f"No query complexity limit on {target.url}",
                        description=(
                            "A highly complex query (100×100×100 nested connections) "
                            "was accepted without complexity/cost rejection. "
                            "This enables resource exhaustion via crafted queries."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Status: {resp.status_code}\n"
                            "Complex query with nested connections accepted"
                        ),
                        remediation=(
                            "Implement query cost analysis (e.g., graphql-cost-analysis). "
                            "Set maximum query cost per request. "
                            "Use persisted queries and disable arbitrary queries."
                        ),
                        cwe=770,
                        tags=["graphql", "query-complexity", "dos", "waaaghlogic"],
                    ))
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return findings
