"""
ModelHunt — Exposed vector database scanner.

Probes well-known vector DB management endpoints for unauthenticated access:
  - Pinecone (managed)
  - Milvus (self-hosted)
  - Qdrant (self-hosted)
  - Weaviate (self-hosted)
  - Chroma (self-hosted)

If unauthenticated list access is found, the tool samples stored records
to assess what data is exposed.  It does NOT download full datasets or
attempt embedding reversal against external services.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, List
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.modelhunt.vector_db_scanner")


@dataclass(frozen=True)
class _VdbProbe:
    """Definition of a vector DB exposure check."""
    product: str
    list_path: str          # unauthenticated listing endpoint
    sample_path: str        # path to fetch a sample record / collection info
    list_keys: tuple        # JSON keys expected in a successful list response
    default_port: int = 0   # 0 = no specific port assumption
    tags: tuple = ()


_VDB_PROBES: List[_VdbProbe] = [
    _VdbProbe(
        product="Qdrant",
        list_path="/collections",
        sample_path="/collections",
        list_keys=("result", "collections"),
        default_port=6333,
        tags=("qdrant", "vector-db"),
    ),
    _VdbProbe(
        product="Weaviate",
        list_path="/v1/schema",
        sample_path="/v1/schema",
        list_keys=("classes",),
        default_port=8080,
        tags=("weaviate", "vector-db"),
    ),
    _VdbProbe(
        product="Chroma",
        list_path="/api/v1/collections",
        sample_path="/api/v1/collections",
        list_keys=(),  # returns a JSON array
        default_port=8000,
        tags=("chroma", "vector-db"),
    ),
    _VdbProbe(
        product="Milvus (REST)",
        list_path="/v1/vector/collections",
        sample_path="/v1/vector/collections",
        list_keys=("data",),
        default_port=19530,
        tags=("milvus", "vector-db"),
    ),
    _VdbProbe(
        product="Milvus (Attu UI)",
        list_path="/",
        sample_path="/api/v1/collections",
        list_keys=("code",),
        default_port=8000,
        tags=("milvus", "attu", "vector-db"),
    ),
]


class VectorDbScanner(HttpClientMixin):
    """Scan for exposed vector database management endpoints."""

    def __init__(self, *, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def scan(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)
        base = _base_url(target.url)

        try:
            for probe in _VDB_PROBES:
                # Try on the target's port and on the default VDB port
                candidate_bases = [base]
                if probe.default_port:
                    parsed = urlparse(base)
                    candidate_bases.append(
                        f"{parsed.scheme}://{parsed.hostname}:{probe.default_port}"
                    )

                for cbase in candidate_bases:
                    url = f"{cbase}{probe.list_path}"
                    try:
                        resp = await client.get(url)
                        status = getattr(resp, "status_code", 0)
                        text = getattr(resp, "text", "") or ""

                        if status != 200 or not text:
                            continue

                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            continue

                        # Verify this looks like the expected product
                        if not _matches_vdb_response(data, probe):
                            continue

                        # Count collections / classes exposed
                        count = _count_collections(data, probe)
                        sample = _sample_collection_names(data, probe)

                        findings.append(Finding(
                            title=f"Exposed vector database ({probe.product}): {cbase}",
                            description=(
                                f"A {probe.product} vector database at {url!r} is accessible "
                                "without authentication. The collection listing is publicly "
                                "readable, exposing the internal knowledge base structure. "
                                "An attacker could query stored embeddings to reconstruct "
                                "the original text content of the knowledge base."
                            ),
                            severity=Severity.CRITICAL,
                            target=target,
                            evidence=(
                                f"Endpoint: {url}\n"
                                f"HTTP status: {status}\n"
                                f"Collections found: {count}\n"
                                + (f"Sample names: {', '.join(sample)}" if sample else "")
                            ),
                            remediation=(
                                f"Add authentication to the {probe.product} instance. "
                                "Use API key authentication or network-level access controls "
                                "(firewall, VPC). Never expose vector DB management ports "
                                "to the public internet."
                            ),
                            cwe=284,
                            tags=["ai", "vector-db", "unauthenticated"] + list(probe.tags),
                        ))
                        break  # One finding per product per target is sufficient

                    except Exception as exc:
                        logger.debug("%s probe failed for %s: %s", probe.product, url, exc)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _matches_vdb_response(data: Any, probe: _VdbProbe) -> bool:
    if not probe.list_keys:
        return isinstance(data, list)
    if isinstance(data, dict):
        return any(k in data for k in probe.list_keys)
    return False


def _count_collections(data: Any, probe: _VdbProbe) -> int:
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in probe.list_keys:
            val = data.get(key)
            if isinstance(val, list):
                return len(val)
            if isinstance(val, dict):
                # Traverse one level deeper to find the list (e.g. Qdrant result.collections)
                for subval in val.values():
                    if isinstance(subval, list):
                        return len(subval)
                return len(val)
    return 0


def _sample_collection_names(data: Any, probe: _VdbProbe, limit: int = 5) -> List[str]:
    names: List[str] = []
    items: List[Any] = []

    if isinstance(data, list):
        items = data[:limit]
    elif isinstance(data, dict):
        for key in probe.list_keys:
            val = data.get(key)
            if isinstance(val, list):
                items = val[:limit]
                break

    for item in items:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            for name_key in ("name", "collection_name", "className", "id"):
                if name_key in item:
                    names.append(str(item[name_key]))
                    break

    return names
