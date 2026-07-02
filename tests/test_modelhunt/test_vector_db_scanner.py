"""Tests for VectorDbScanner — exposed vector database detection."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.modelhunt.vector_db_scanner import VectorDbScanner, _base_url, _count_collections


class _FakeResponse:
    def __init__(self, text: str = "", status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class _AlwaysReturnsClient:
    """Returns a canned response for every GET."""
    def __init__(self, response_text: str, status: int = 200):
        self._text = response_text
        self._status = status

    async def get(self, url: str, **kw) -> _FakeResponse:
        return _FakeResponse(text=self._text, status_code=self._status)

    async def close(self) -> None:
        pass


class _AlwaysFailsClient:
    async def get(self, *a, **kw):
        raise ConnectionError("refused")
    async def close(self): pass


@pytest.mark.asyncio
class TestVectorDbScanner:

    async def test_detects_exposed_qdrant(self):
        qdrant_response = json.dumps({
            "result": {"collections": [{"name": "documents"}, {"name": "embeddings"}]},
            "status": "ok",
        })
        client = _AlwaysReturnsClient(qdrant_response)
        scanner = VectorDbScanner(http_client=client)
        target = Target(url="https://qdrant.example.com:6333")

        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("qdrant" in " ".join(f.tags).lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_detects_exposed_weaviate(self):
        weaviate_response = json.dumps({
            "classes": [
                {"class": "Document", "vectorizer": "text2vec-openai"},
                {"class": "Product", "vectorizer": "text2vec-cohere"},
            ]
        })
        client = _AlwaysReturnsClient(weaviate_response)
        scanner = VectorDbScanner(http_client=client)
        target = Target(url="https://weaviate.example.com:8080")

        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("weaviate" in " ".join(f.tags).lower() for f in findings)

    async def test_detects_exposed_chroma(self):
        chroma_response = json.dumps([
            {"name": "my_collection", "id": "abc123"},
            {"name": "embeddings", "id": "def456"},
        ])
        client = _AlwaysReturnsClient(chroma_response)
        scanner = VectorDbScanner(http_client=client)
        target = Target(url="https://chroma.example.com:8000")

        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("chroma" in " ".join(f.tags).lower() for f in findings)

    async def test_no_finding_when_404(self):
        client = _AlwaysReturnsClient("{}", status=404)
        scanner = VectorDbScanner(http_client=client)
        target = Target(url="https://example.com")

        findings = await scanner.scan(target)
        assert findings == []

    async def test_no_finding_on_connection_error(self):
        scanner = VectorDbScanner(http_client=_AlwaysFailsClient())
        target = Target(url="https://example.com")

        findings = await scanner.scan(target)
        assert findings == []

    async def test_no_finding_for_non_vdb_json(self):
        other_json = json.dumps({"status": "ok", "message": "Hello"})
        client = _AlwaysReturnsClient(other_json)
        scanner = VectorDbScanner(http_client=client)
        target = Target(url="https://some-api.example.com")

        findings = await scanner.scan(target)
        assert findings == []


class TestVectorDbHelpers:
    """Sync utility tests — no async, no event loop needed."""

    def test_base_url_strips_path(self):
        assert _base_url("https://example.com/some/path") == "https://example.com"

    def test_count_collections_from_list(self):
        from krumpa.modelhunt.vector_db_scanner import _VDB_PROBES
        chroma_probe = next(p for p in _VDB_PROBES if p.product == "Chroma")
        data = [{"name": "a"}, {"name": "b"}]
        assert _count_collections(data, chroma_probe) == 2

    def test_count_collections_from_nested_dict(self):
        from krumpa.modelhunt.vector_db_scanner import _VDB_PROBES
        qdrant_probe = next(p for p in _VDB_PROBES if p.product == "Qdrant")
        data = {"result": {"collections": [{"name": "x"}, {"name": "y"}]}}
        assert _count_collections(data, qdrant_probe) == 2
