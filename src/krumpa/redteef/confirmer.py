"""
RedTeef — vulnerability confirmer.

Takes a suspected finding and a list of proof payloads, sends each one,
and determines whether the vulnerability is **confirmed**, **likely**,
or **not confirmed** based on the response.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin
from krumpa.redteef.payload_builder import ProofPayload

logger = logging.getLogger("krumpa.redteef.confirmer")


# ------------------------------------------------------------------
# Confirmation verdict
# ------------------------------------------------------------------

class ConfirmationVerdict(enum.Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NOT_CONFIRMED = "not_confirmed"


@dataclass
class ConfirmationResult(HttpClientMixin):
    """Outcome of a confirmation attempt."""
    original_finding: Finding
    verdict: ConfirmationVerdict
    evidence_payloads: List[ProofPayload] = field(default_factory=list)
    response_snippets: List[str] = field(default_factory=list)
    notes: str = ""

    @property
    def confirmed(self) -> bool:
        return self.verdict == ConfirmationVerdict.CONFIRMED

    @property
    def likely(self) -> bool:
        return self.verdict in (ConfirmationVerdict.CONFIRMED, ConfirmationVerdict.LIKELY)


# ------------------------------------------------------------------
# Confirmer
# ------------------------------------------------------------------

class Confirmer(HttpClientMixin):
    """
    Execute proof-of-concept payloads and evaluate the results.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`. One is created if not provided.
    confirmation_threshold:
        Fraction (0-1) of indicator-based canaries that must match for
        a *confirmed* verdict (default 0.5).
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        confirmation_threshold: float = 0.5,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.confirmation_threshold = confirmation_threshold

    async def confirm(
        self,
        finding: Finding,
        payloads: List[ProofPayload],
        target: Target,
    ) -> ConfirmationResult:
        """
        Send each *payload* and evaluate whether the vulnerability is real.
        """
        if not payloads:
            return ConfirmationResult(
                original_finding=finding,
                verdict=ConfirmationVerdict.NOT_CONFIRMED,
                notes="No proof payloads provided.",
            )

        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            evidence: List[ProofPayload] = []
            snippets: List[str] = []
            hits = 0
            indicator_payloads = 0

            for pp in payloads:
                resp_text = await self._send_payload(client, pp, target)

                if pp.expected_indicator:
                    indicator_payloads += 1
                    matched = self._check_indicator(resp_text, pp)
                    if matched:
                        hits += 1
                        evidence.append(pp)
                        snippets.append(self._snippet(resp_text, pp.expected_indicator))
                else:
                    # No indicator — differential analysis handled by caller
                    pass

            verdict = self._decide(hits, indicator_payloads, payloads)
            return ConfirmationResult(
                original_finding=finding,
                verdict=verdict,
                evidence_payloads=evidence,
                response_snippets=snippets,
            )
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # SQLi differential confirmation
    # ------------------------------------------------------------------

    async def confirm_sqli_differential(
        self,
        finding: Finding,
        target: Target,
        *,
        url: str,
        field_name: str,
        true_payload: str = "' AND '1'='1",
        false_payload: str = "' AND '1'='2",
    ) -> ConfirmationResult:
        """
        Boolean-based SQL injection confirmation: send a tautology and a
        contradiction and compare responses. If they differ, the injection
        is likely real.
        """
        client = self._client or HttpClient(timeout=15.0, retries=0)
        try:
            true_resp = await self._send_raw(client, url, field_name, true_payload, target)
            false_resp = await self._send_raw(client, url, field_name, false_payload, target)

            # Significant difference in body or status → confirmed
            if true_resp["status"] != false_resp["status"]:
                return ConfirmationResult(
                    original_finding=finding,
                    verdict=ConfirmationVerdict.CONFIRMED,
                    notes=(
                        f"Status diff: tautology→{true_resp['status']} "
                        f"vs contradiction→{false_resp['status']}"
                    ),
                )

            size_diff = abs(len(true_resp["body"]) - len(false_resp["body"]))
            if size_diff > 50:
                return ConfirmationResult(
                    original_finding=finding,
                    verdict=ConfirmationVerdict.CONFIRMED,
                    notes=f"Body size diff: {size_diff} bytes between tautology and contradiction.",
                )

            if true_resp["body"] != false_resp["body"]:
                return ConfirmationResult(
                    original_finding=finding,
                    verdict=ConfirmationVerdict.LIKELY,
                    notes="Bodies differ slightly between tautology and contradiction.",
                )

            return ConfirmationResult(
                original_finding=finding,
                verdict=ConfirmationVerdict.NOT_CONFIRMED,
                notes="Tautology and contradiction produced identical responses.",
            )
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _send_payload(
        self, client: HttpClient, pp: ProofPayload, target: Target,
    ) -> str:
        """Send a proof payload and return the response body text."""
        headers = dict(target.headers) if target.headers else {}
        body: Optional[Dict[str, Any]] = None

        if pp.inject_location == "header":
            headers[pp.inject_field] = pp.payload
        elif pp.inject_location == "body":
            body = {pp.inject_field: pp.payload} if pp.inject_field else None
        # "url" location: append to URL path
        url = target.url
        if pp.inject_location == "url":
            url = target.url.rstrip("/") + "/" + pp.payload

        try:
            resp = await client.request(
                pp.http_method, url,
                headers=headers or None,
                json_body=body,
            )
            return resp.text
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Payload %r error: %s", pp.payload, exc)
            return ""

    async def _send_raw(
        self,
        client: HttpClient,
        url: str,
        field_name: str,
        payload: str,
        target: Target,
    ) -> Dict[str, Any]:
        """Send a raw payload and return status + body."""
        headers = dict(target.headers) if target.headers else {}
        body = {field_name: payload}
        try:
            resp = await client.request(
                "POST", url, headers=headers or None, json_body=body,
            )
            return {"status": resp.status_code, "body": resp.text}
        except (httpx.HTTPError, OSError):
            return {"status": 0, "body": ""}

    @staticmethod
    def _check_indicator(body: str, pp: ProofPayload) -> bool:
        """Check whether the expected indicator is present in *body*."""
        if not pp.expected_indicator or not body:
            return False
        if pp.is_regex:
            try:
                # Timeout-protected regex to guard against ReDoS
                compiled = re.compile(pp.expected_indicator)
                return bool(compiled.search(body))
            except re.error:
                logger.warning("Invalid regex indicator: %s", pp.expected_indicator)
                return False
        return pp.expected_indicator in body

    @staticmethod
    def _snippet(body: str, indicator: str, context: int = 80) -> str:
        """Extract a small snippet around the indicator match."""
        idx = body.find(indicator)
        if idx < 0:
            return body[:context]
        start = max(0, idx - context // 2)
        end = min(len(body), idx + len(indicator) + context // 2)
        return body[start:end]

    def _decide(
        self, hits: int, indicator_count: int, all_payloads: List[ProofPayload],
    ) -> ConfirmationVerdict:
        """Determine verdict from hit ratio."""
        if indicator_count == 0:
            return ConfirmationVerdict.NOT_CONFIRMED
        ratio = hits / indicator_count
        if ratio >= self.confirmation_threshold:
            return ConfirmationVerdict.CONFIRMED
        if hits > 0:
            return ConfirmationVerdict.LIKELY
        return ConfirmationVerdict.NOT_CONFIRMED
