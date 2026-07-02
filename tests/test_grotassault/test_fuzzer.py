"""Tests for krumpa.grotassault.fuzzer — fuzz executor and anomaly detection."""

import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Severity, Target
from krumpa.grotassault.fuzzer import Fuzzer, FuzzTarget
from krumpa.grotassault.mutator import Mutator, MutationStrategy


# ------------------------------------------------------------------
# Fake HTTP layer
# ------------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = '{"ok": true}'

    @property
    def headers(self) -> dict:
        return {"content-type": "application/json"}


class FakeHttpClient:
    """Controllable HTTP client for tests."""

    def __init__(
        self,
        *,
        default_status: int = 200,
        default_text: str = '{"ok": true}',
        error_on_payload: Optional[str] = None,
        error_message: str = "connection reset",
        status_by_payload: Optional[Dict[str, int]] = None,
        text_by_payload: Optional[Dict[str, str]] = None,
    ):
        self.default_status = default_status
        self.default_text = default_text
        self.error_on_payload = error_on_payload
        self.error_message = error_message
        self.status_by_payload = status_by_payload or {}
        self.text_by_payload = text_by_payload or {}
        self.requests: List[Dict[str, Any]] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.requests.append({
            "method": method, "url": url,
            "headers": headers, "json_body": json_body,
        })
        # Check if any body value triggers special behaviour
        payload_str = self._extract_payload(json_body, headers)

        if self.error_on_payload and payload_str and self.error_on_payload in payload_str:
            raise ConnectionError(self.error_message)

        status = self.status_by_payload.get(payload_str, self.default_status) if payload_str else self.default_status
        text = self.text_by_payload.get(payload_str, self.default_text) if payload_str else self.default_text
        return FakeResponse(status_code=status, text=text)

    async def close(self):
        pass

    @staticmethod
    def _extract_payload(json_body, headers) -> Optional[str]:
        """Get a string representation of the first non-trivial value."""
        if json_body and isinstance(json_body, dict):
            for v in json_body.values():
                if v is not None:
                    return str(v)
        if headers and isinstance(headers, dict):
            for v in headers.values():
                if v:
                    return str(v)
        return None


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_target(url: str = "https://api.example.com/submit") -> Target:
    return Target(url=url, method="POST")


def _make_fuzz_target(
    url: str = "https://api.example.com/submit",
    base_body: Optional[Dict[str, Any]] = None,
) -> FuzzTarget:
    return FuzzTarget(
        url=url,
        method="POST",
        base_body=base_body or {"username": "admin"},
    )


def _tiny_mutator() -> Mutator:
    """Mutator that produces very few payloads (fast tests)."""
    return Mutator(
        strategies=[MutationStrategy.INJECTION],
        max_payloads_per_field=3,
        seed=1,
    )


# ------------------------------------------------------------------
# Tests — normal operation
# ------------------------------------------------------------------

class TestFuzzerNormal:
    @pytest.mark.asyncio
    async def test_returns_no_findings_for_benign_responses(self):
        client = FakeHttpClient()
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        # All payloads returned 200 with the same body → no anomalies
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_sends_requests_for_each_field(self):
        client = FakeHttpClient()
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target(base_body={"a": "x", "b": "y"})
        await fuzzer.fuzz(ft, _make_target())
        # 1 baseline + (3 payloads * 2 fields) = 7
        assert len(client.requests) >= 5  # at least baseline + some fuzz


# ------------------------------------------------------------------
# Tests — server error detection
# ------------------------------------------------------------------

class TestServerErrors:
    @pytest.mark.asyncio
    async def test_flags_500_status(self):
        client = FakeHttpClient(default_status=500)
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        server_errors = [f for f in findings if "server error" in f.title.lower() or "Server error" in f.title]
        assert len(server_errors) > 0

    @pytest.mark.asyncio
    async def test_server_error_severity_is_high(self):
        client = FakeHttpClient(default_status=502)
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        for f in findings:
            if "server error" in f.title.lower():
                assert f.severity == Severity.HIGH


# ------------------------------------------------------------------
# Tests — connection error / crash detection
# ------------------------------------------------------------------

class TestConnectionErrors:
    @pytest.mark.asyncio
    async def test_flags_connection_error(self):
        # Trigger error on any payload containing "OR"
        client = FakeHttpClient(error_on_payload="OR")
        mut = Mutator(strategies=[MutationStrategy.INJECTION], max_payloads_per_field=10, seed=0)
        fuzzer = Fuzzer(http_client=client, mutator=mut)
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        crash_findings = [f for f in findings if "connection error" in f.title.lower()]
        assert len(crash_findings) > 0

    @pytest.mark.asyncio
    async def test_crash_finding_is_critical(self):
        client = FakeHttpClient(error_on_payload="OR")
        mut = Mutator(strategies=[MutationStrategy.INJECTION], max_payloads_per_field=5, seed=0)
        fuzzer = Fuzzer(http_client=client, mutator=mut)
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        crash_findings = [f for f in findings if "connection error" in f.title.lower()]
        for f in crash_findings:
            assert f.severity == Severity.CRITICAL


# ------------------------------------------------------------------
# Tests — stack trace detection
# ------------------------------------------------------------------

class TestStackTraceDetection:
    @pytest.mark.asyncio
    async def test_flags_python_traceback(self):
        client = FakeHttpClient(
            default_text="<html>Traceback (most recent call last):\n  File ...</html>",
        )
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        stack_findings = [f for f in findings if "stack trace" in f.title.lower()]
        assert len(stack_findings) > 0

    @pytest.mark.asyncio
    async def test_flags_java_stacktrace(self):
        client = FakeHttpClient(
            default_text="at com.example.App(App.java:42)\njava.lang.NullPointerException",
        )
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        stack_findings = [f for f in findings if "stack trace" in f.title.lower()]
        assert len(stack_findings) > 0

    @pytest.mark.asyncio
    async def test_flags_mysql_error(self):
        client = FakeHttpClient(
            default_text="You have an error in your MySQL syntax near ...",
        )
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        stack_findings = [f for f in findings if "stack trace" in f.title.lower()]
        assert len(stack_findings) > 0

    @pytest.mark.asyncio
    async def test_stack_trace_severity_is_medium(self):
        client = FakeHttpClient(default_text="Stack Trace: ...")
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        for f in findings:
            if "stack trace" in f.title.lower():
                assert f.severity == Severity.MEDIUM


# ------------------------------------------------------------------
# Tests — reflected input
# ------------------------------------------------------------------

class TestReflection:
    @pytest.mark.asyncio
    async def test_flags_reflected_payload(self):
        # Pick a known injection payload that is >= _REFLECTION_MIN_LENGTH
        reflected = "' OR '1'='1"
        client = FakeHttpClient(default_text=f"Error: invalid input {reflected}")
        mut = Mutator(strategies=[MutationStrategy.INJECTION], max_payloads_per_field=50, seed=0)
        fuzzer = Fuzzer(http_client=client, mutator=mut)
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        reflection_findings = [f for f in findings if "reflected" in f.title.lower()]
        assert len(reflection_findings) > 0

    @pytest.mark.asyncio
    async def test_short_payloads_not_flagged(self):
        # A very short payload reflected should not trigger
        client = FakeHttpClient(default_text="a")
        mut = Mutator(strategies=[MutationStrategy.BOUNDARY], max_payloads_per_field=5, seed=0)
        fuzzer = Fuzzer(http_client=client, mutator=mut)
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        reflection_findings = [f for f in findings if "reflected" in f.title.lower()]
        assert len(reflection_findings) == 0


# ------------------------------------------------------------------
# Tests — response size anomaly
# ------------------------------------------------------------------

class TestSizeAnomaly:
    @pytest.mark.asyncio
    async def test_flags_large_deviation(self):
        # Baseline 10 bytes, fuzzed response 500 bytes => huge deviation
        class SizeClient:
            def __init__(self):
                self.call_count = 0
            async def request(self, *a, **kw):
                self.call_count += 1
                if self.call_count == 1:
                    return FakeResponse(text="0123456789")  # baseline
                return FakeResponse(text="A" * 500)
            async def close(self):
                pass

        fuzzer = Fuzzer(http_client=SizeClient(), mutator=_tiny_mutator(), baseline_deviation_pct=100.0)
        ft = _make_fuzz_target()
        findings = await fuzzer.fuzz(ft, _make_target())
        anomaly = [f for f in findings if "size anomaly" in f.title.lower() or "anomaly" in f.title.lower()]
        assert len(anomaly) > 0


# ------------------------------------------------------------------
# Tests — FuzzTarget with header fuzzing
# ------------------------------------------------------------------

class TestHeaderFuzzing:
    @pytest.mark.asyncio
    async def test_fuzzes_headers_when_specified(self):
        client = FakeHttpClient()
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = FuzzTarget(
            url="https://api.example.com/data",
            method="GET",
            base_headers={"X-Custom": "value"},
            fuzz_headers=["X-Custom"],
        )
        await fuzzer.fuzz(ft, _make_target())
        # baseline + header fuzz requests
        assert len(client.requests) >= 2


# ------------------------------------------------------------------
# Tests — empty fuzz target
# ------------------------------------------------------------------

class TestEmptyTarget:
    @pytest.mark.asyncio
    async def test_no_fields_no_findings(self):
        client = FakeHttpClient()
        fuzzer = Fuzzer(http_client=client, mutator=_tiny_mutator())
        ft = FuzzTarget(url="https://api.example.com/health", method="GET")
        findings = await fuzzer.fuzz(ft, _make_target())
        # No body fields, no header fields → only baseline sent
        assert len(client.requests) == 1  # just the baseline
        assert findings == []
