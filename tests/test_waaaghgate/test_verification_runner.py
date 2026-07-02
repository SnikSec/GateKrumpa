"""Tests for VerificationRunner — one-click verification (1CV)."""

from __future__ import annotations

import pytest

from krumpa.core import Finding, ScanContext, Severity
from krumpa.waaaghgate.verification_runner import (
    VerificationPath, VerificationResult, VerificationRunner,
)


class _FakeHttpClient:
    def __init__(self, response_text: str, status: int = 200):
        self._text = response_text
        self._status = status

    async def request(self, method: str, url: str, **kw):
        return type("R", (), {"text": self._text, "status_code": self._status, "headers": {}})()

    async def close(self): pass


class TestVerificationPath:

    def test_round_trip_serialisation(self):
        path = VerificationPath(
            finding_id="abc123",
            module="grotassault",
            target_url="https://example.com/api",
            method="POST",
            payload="' OR '1'='1",
            inject_location="body",
            inject_field="username",
            expected_indicator="root:x:0:0",
        )
        d = path.to_dict()
        restored = VerificationPath.from_dict(d)
        assert restored.finding_id == path.finding_id
        assert restored.payload == path.payload
        assert restored.expected_indicator == path.expected_indicator


class TestVerificationResult:

    def test_to_dict_structure(self):
        result = VerificationResult(
            finding_id="abc",
            status="patched",
            evidence="Indicator not found",
        )
        d = result.to_dict()
        assert d["finding_id"] == "abc"
        assert d["status"] == "patched"
        assert "evidence" in d


@pytest.mark.asyncio
class TestVerificationRunner:

    def _ctx_with_path(self, path: VerificationPath, http_client=None) -> ScanContext:
        ctx = ScanContext()
        ctx.metadata["verification_paths"] = {path.finding_id: path.to_dict()}
        ctx.http_client = http_client
        return ctx

    async def test_returns_verified_when_indicator_found(self):
        path = VerificationPath(
            finding_id="f1",
            module="grotassault",
            target_url="https://example.com/login",
            method="POST",
            payload="' OR '1'='1",
            inject_location="body",
            inject_field="password",
            expected_indicator="root:x:0:0",
        )
        client = _FakeHttpClient("root:x:0:0:root:/root:/bin/bash")
        ctx = self._ctx_with_path(path, client)

        result = await VerificationRunner().verify("f1", ctx)
        assert result.status == "verified"

    async def test_returns_patched_when_indicator_absent(self):
        path = VerificationPath(
            finding_id="f2",
            module="grotassault",
            target_url="https://example.com/login",
            method="POST",
            payload="payload",
            expected_indicator="SECRET_MARKER_XYZ",
        )
        client = _FakeHttpClient("Access denied — patch applied.")
        ctx = self._ctx_with_path(path, client)

        result = await VerificationRunner().verify("f2", ctx)
        assert result.status == "patched"

    async def test_returns_inconclusive_when_no_path(self):
        ctx = ScanContext()
        ctx.metadata["verification_paths"] = {}
        ctx.http_client = _FakeHttpClient("")

        result = await VerificationRunner().verify("nonexistent", ctx)
        assert result.status == "inconclusive"

    async def test_returns_inconclusive_when_no_http_client(self):
        path = VerificationPath(finding_id="f3", module="test", target_url="https://example.com")
        ctx = ScanContext()
        ctx.metadata["verification_paths"] = {"f3": path.to_dict()}
        ctx.http_client = None

        result = await VerificationRunner().verify("f3", ctx)
        assert result.status == "inconclusive"

    async def test_returns_inconclusive_on_connection_error(self):
        class _FailClient:
            async def request(self, *a, **kw): raise ConnectionError("refused")
            async def close(self): pass

        path = VerificationPath(
            finding_id="f4",
            module="test",
            target_url="https://example.com",
            expected_indicator="MARKER",
        )
        ctx = self._ctx_with_path(path, _FailClient())

        result = await VerificationRunner().verify("f4", ctx)
        assert result.status == "inconclusive"

    async def test_regex_indicator_matching(self):
        path = VerificationPath(
            finding_id="f5",
            module="grotassault",
            target_url="https://example.com",
            method="GET",
            expected_indicator=r"root:\w+:0:0:",
            is_regex=True,
        )
        client = _FakeHttpClient("root:x:0:0:root:/root:/bin/bash")
        ctx = self._ctx_with_path(path, client)

        result = await VerificationRunner().verify("f5", ctx)
        assert result.status == "verified"

    async def test_store_and_retrieve_path(self):
        finding = Finding(id="xyz789", title="Test", severity=Severity.HIGH)
        path = VerificationPath(
            finding_id="xyz789",
            module="redteef",
            target_url="https://example.com",
            expected_indicator="CANARY",
        )
        ctx = ScanContext()
        ctx.metadata["verification_paths"] = {}
        ctx.http_client = _FakeHttpClient("CANARY_IS_HERE")

        VerificationRunner().store(finding, path, ctx)
        assert "xyz789" in ctx.metadata["verification_paths"]

        result = await VerificationRunner().verify("xyz789", ctx)
        assert result.status == "verified"
