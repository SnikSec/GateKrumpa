"""
OpenKrump — API specification auto-discovery.

Probes well-known paths where API specifications (OpenAPI / Swagger,
GraphQL, WADL, etc.) are commonly served.  Discovered specs are fed
back into the OpenKrump pipeline for further analysis.

References:
  - OWASP API Security Top 10 — API9: Improper Inventory Management
  - CWE-200: Exposure of Sensitive Information
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.openkrump.spec_discovery")


# Well-known paths where API specs are commonly served
_SPEC_PATHS: List[Dict[str, str]] = [
    # OpenAPI / Swagger
    {"path": "/openapi.json", "type": "openapi"},
    {"path": "/openapi.yaml", "type": "openapi"},
    {"path": "/openapi.yml", "type": "openapi"},
    {"path": "/swagger.json", "type": "swagger"},
    {"path": "/swagger.yaml", "type": "swagger"},
    {"path": "/swagger/v1/swagger.json", "type": "swagger"},
    {"path": "/api-docs", "type": "swagger"},
    {"path": "/api-docs.json", "type": "swagger"},
    {"path": "/v1/api-docs", "type": "swagger"},
    {"path": "/v2/api-docs", "type": "swagger"},
    {"path": "/v3/api-docs", "type": "openapi"},
    {"path": "/docs", "type": "openapi"},
    {"path": "/redoc", "type": "openapi"},
    {"path": "/api/swagger.json", "type": "swagger"},
    {"path": "/api/openapi.json", "type": "openapi"},
    {"path": "/.well-known/openapi", "type": "openapi"},

    # GraphQL
    {"path": "/graphql", "type": "graphql"},
    {"path": "/gql", "type": "graphql"},
    {"path": "/graphiql", "type": "graphql"},
    {"path": "/altair", "type": "graphql"},
    {"path": "/playground", "type": "graphql"},
    {"path": "/v1/graphql", "type": "graphql"},

    # WADL (legacy SOAP/REST)
    {"path": "/application.wadl", "type": "wadl"},

    # gRPC reflection (via gRPC-Web / REST gateway)
    {"path": "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "type": "grpc"},
]


class SpecDiscovery(HttpClientMixin):
    """Auto-discover API specification endpoints."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def discover(
        self,
        base_url: str,
        *,
        target: Optional[Target] = None,
    ) -> List[Finding]:
        """Probe well-known spec paths and report any that respond."""
        findings: List[Finding] = []
        discovered_specs: List[Dict[str, str]] = []
        client = self._client or HttpClient(timeout=10.0, retries=1)
        _t = target or Target(url=base_url)

        try:
            for entry in _SPEC_PATHS:
                url = urljoin(base_url, entry["path"])
                spec_type = entry["type"]

                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    if len(resp.text) < 20:
                        continue

                    # Quick validation that it looks like a real spec
                    if spec_type in ("openapi", "swagger"):
                        if not self._looks_like_openapi(resp.text):
                            continue
                    elif spec_type == "graphql":
                        if not self._looks_like_graphql(resp.text, resp.status_code):
                            continue

                    discovered_specs.append({
                        "url": url,
                        "type": spec_type,
                        "size": str(len(resp.text)),
                    })
                    logger.info("Discovered %s spec at %s", spec_type, url)

                except (httpx.HTTPError, OSError, ValueError):
                    continue

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        # Generate findings
        if discovered_specs:
            for spec in discovered_specs:
                findings.append(Finding(
                    title=f"API specification exposed: {spec['type']} at {spec['url']}",
                    description=(
                        f"An API specification ({spec['type']}) was found publicly "
                        f"accessible at {spec['url']} ({spec['size']} bytes). "
                        f"This reveals the full API surface to potential attackers."
                    ),
                    severity=Severity.LOW,
                    target=Target(url=spec["url"], method="GET"),
                    evidence=f"type={spec['type']}, size={spec['size']}",
                    remediation=(
                        "Restrict API specification endpoints to authorised users "
                        "or internal networks. If public access is intended, "
                        "ensure all documented endpoints are properly secured."
                    ),
                    cwe=200,
                    tags=["spec-discovery", "api", "information-disclosure"],
                ))

        return findings

    @property
    def discovered_specs(self) -> List[Dict[str, str]]:
        """Return specs discovered in the last scan (for pipeline use)."""
        return []  # stateless — callers should use findings

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_openapi(text: str) -> bool:
        """Heuristic check that text is probably an OpenAPI/Swagger spec."""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return any(
                    k in data
                    for k in ("openapi", "swagger", "paths", "info")
                )
        except (json.JSONDecodeError, TypeError):
            pass
        # YAML check (simple keyword scan)
        lower = text[:2000].lower()
        return any(kw in lower for kw in ("openapi:", "swagger:", "paths:"))

    @staticmethod
    def _looks_like_graphql(text: str, status_code: int) -> bool:
        """Heuristic: does the response look like a GraphQL endpoint?"""
        if status_code != 200:
            return False
        lower = text[:2000].lower()
        return any(
            kw in lower
            for kw in ("graphql", "graphiql", "__schema", "query", "mutation")
        )
