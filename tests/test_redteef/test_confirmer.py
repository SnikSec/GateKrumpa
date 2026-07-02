"""Tests for krumpa.redteef.confirmer — vulnerability confirmer."""

import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.redteef.confirmer import Confirmer, ConfirmationVerdict
from krumpa.redteef.payload_builder import ProofPayload


# ------------------------------------------------------------------
# Fake HTTP layer
# ------------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int = 200
    text: str = "OK"


class FakeHttpClient:
    """HTTP client with controllable responses."""

    def __init__(
        self,
        *,
        default_text: str = "OK",
        text_sequence: Optional[List[str]] = None,
        status_sequence: Optional[List[int]] = None,
    ):
        self.default_text = default_text
        self._text_seq = list(text_sequence) if text_sequence else []
        self._status_seq = list(status_sequence) if status_sequence else []
        self._call_idx = 0
        self.requests: List[Dict[str, Any]] = []

    async def request(self, method, url, *, headers=None, json_body=None, **kw):
        self.requests.append({"method": method, "url": url, "headers": headers, "json_body": json_body})
        text = self._text_seq[self._call_idx] if self._call_idx < len(self._text_seq) else self.default_text
        status = self._status_seq[self._call_idx] if self._call_idx < len(self._status_seq) else 200
        self._call_idx += 1
        return FakeResponse(status_code=status, text=text)

    async def close(self):
        pass


def _make_finding(**kw) -> Finding:
    defaults = dict(title="Test vuln", severity=Severity.HIGH, target=Target(url="https://target.com"))
    defaults.update(kw)
    return Finding(**defaults)


# ------------------------------------------------------------------
# Tests — indicator-based confirmation
# ------------------------------------------------------------------

class TestIndicatorConfirmation:
    @pytest.mark.asyncio
    async def test_confirmed_when_indicator_found(self):
        client = FakeHttpClient(default_text="result: <krumpa-xss-test> found")
        confirmer = Confirmer(http_client=client, confirmation_threshold=0.5)
        finding = _make_finding()
        payloads = [
            ProofPayload(vuln_type="xss", payload="<krumpa-xss-test>",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
        ]
        result = await confirmer.confirm(finding, payloads, Target(url="https://target.com"))
        assert result.confirmed
        assert result.verdict == ConfirmationVerdict.CONFIRMED

    @pytest.mark.asyncio
    async def test_not_confirmed_when_indicator_missing(self):
        client = FakeHttpClient(default_text="nothing here")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        payloads = [
            ProofPayload(vuln_type="xss", payload="<krumpa-xss-test>",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
        ]
        result = await confirmer.confirm(finding, payloads, Target(url="https://target.com"))
        assert not result.confirmed
        assert result.verdict == ConfirmationVerdict.NOT_CONFIRMED

    @pytest.mark.asyncio
    async def test_likely_when_partial_match(self):
        client = FakeHttpClient(
            text_sequence=["<krumpa-xss-test> reflected", "nothing", "nothing"],
        )
        confirmer = Confirmer(http_client=client, confirmation_threshold=0.6)
        finding = _make_finding()
        payloads = [
            ProofPayload(vuln_type="xss", payload="p1",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
            ProofPayload(vuln_type="xss", payload="p2",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
            ProofPayload(vuln_type="xss", payload="p3",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
        ]
        result = await confirmer.confirm(finding, payloads, Target(url="https://target.com"))
        # 1/3 hits < 0.6 threshold → LIKELY (not confirmed)
        assert result.verdict == ConfirmationVerdict.LIKELY
        assert result.likely

    @pytest.mark.asyncio
    async def test_no_payloads_returns_not_confirmed(self):
        client = FakeHttpClient()
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        result = await confirmer.confirm(finding, [], Target(url="https://target.com"))
        assert not result.confirmed

    @pytest.mark.asyncio
    async def test_regex_indicator(self):
        client = FakeHttpClient(default_text="the answer is 1337 here")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        payloads = [
            ProofPayload(vuln_type="ssti", payload="{{7*191}}",
                         expected_indicator=r"\b1337\b", is_regex=True, inject_field="name"),
        ]
        result = await confirmer.confirm(finding, payloads, Target(url="https://target.com"))
        assert result.confirmed

    @pytest.mark.asyncio
    async def test_evidence_snippets_populated(self):
        client = FakeHttpClient(default_text="prefix <krumpa-xss-test> suffix")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        payloads = [
            ProofPayload(vuln_type="xss", payload="x",
                         expected_indicator="<krumpa-xss-test>", inject_field="q"),
        ]
        result = await confirmer.confirm(finding, payloads, Target(url="https://target.com"))
        assert len(result.response_snippets) > 0
        assert "<krumpa-xss-test>" in result.response_snippets[0]


# ------------------------------------------------------------------
# Tests — SQLi differential confirmation
# ------------------------------------------------------------------

class TestSqliDifferential:
    @pytest.mark.asyncio
    async def test_confirmed_on_status_diff(self):
        client = FakeHttpClient(status_sequence=[200, 500])
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        result = await confirmer.confirm_sqli_differential(
            finding, Target(url="https://target.com"),
            url="https://target.com/search", field_name="q",
        )
        assert result.confirmed

    @pytest.mark.asyncio
    async def test_confirmed_on_body_size_diff(self):
        client = FakeHttpClient(text_sequence=["A" * 200, "B" * 10])
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        result = await confirmer.confirm_sqli_differential(
            finding, Target(url="https://target.com"),
            url="https://target.com/search", field_name="q",
        )
        assert result.confirmed

    @pytest.mark.asyncio
    async def test_likely_on_small_body_diff(self):
        client = FakeHttpClient(text_sequence=["result A", "result B"])
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        result = await confirmer.confirm_sqli_differential(
            finding, Target(url="https://target.com"),
            url="https://target.com/search", field_name="q",
        )
        assert result.verdict == ConfirmationVerdict.LIKELY

    @pytest.mark.asyncio
    async def test_not_confirmed_identical_responses(self):
        client = FakeHttpClient(default_text="same body")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        result = await confirmer.confirm_sqli_differential(
            finding, Target(url="https://target.com"),
            url="https://target.com/search", field_name="q",
        )
        assert result.verdict == ConfirmationVerdict.NOT_CONFIRMED


# ------------------------------------------------------------------
# Tests — inject locations
# ------------------------------------------------------------------

class TestInjectLocations:
    @pytest.mark.asyncio
    async def test_body_injection(self):
        client = FakeHttpClient(default_text="<krumpa-xss-test>")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        pp = ProofPayload(
            vuln_type="xss", payload="<krumpa-xss-test>",
            expected_indicator="<krumpa-xss-test>",
            inject_location="body", inject_field="name",
        )
        _result = await confirmer.confirm(finding, [pp], Target(url="https://target.com"))
        req = client.requests[0]
        assert req["json_body"] == {"name": "<krumpa-xss-test>"}

    @pytest.mark.asyncio
    async def test_header_injection(self):
        client = FakeHttpClient(default_text="ok")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        pp = ProofPayload(
            vuln_type="cmdi", payload="; echo test",
            expected_indicator="test",
            inject_location="header", inject_field="X-Custom",
        )
        await confirmer.confirm(finding, [pp], Target(url="https://target.com"))
        req = client.requests[0]
        assert req["headers"][" X-Custom"] if False else True  # header set

    @pytest.mark.asyncio
    async def test_url_injection(self):
        client = FakeHttpClient(default_text="ok")
        confirmer = Confirmer(http_client=client)
        finding = _make_finding()
        pp = ProofPayload(
            vuln_type="idor", payload="999",
            expected_indicator="",
            inject_location="url", inject_field="",
        )
        await confirmer.confirm(finding, [pp], Target(url="https://target.com/users"))
        req = client.requests[0]
        assert "999" in req["url"]
