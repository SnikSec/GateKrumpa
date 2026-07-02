"""
WaaaghGate — One-click verification (1CV) runner.

Stores the exact attack path used to discover each finding and re-executes
that precise sequence to confirm whether a patch has been applied.

Usage::

    # Store a verification path when a finding is confirmed
    runner = VerificationRunner()
    runner.store(finding, verification_path)

    # Later — re-run the same path
    result = await runner.verify(finding_id, ctx)
    # result.status is "verified", "patched", or "inconclusive"
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from krumpa.core import Finding, ScanContext

logger = logging.getLogger("krumpa.waaaghgate.verification_runner")


@dataclass
class VerificationPath:
    """The minimal information needed to replay a single finding's exploit path.

    Attributes
    ----------
    finding_id:
        ID of the :class:`Finding` this path verifies.
    module:
        Module name that produced the finding.
    target_url:
        URL of the target.
    method:
        HTTP method used.
    payload:
        The payload or parameter value that triggered the finding.
    inject_location:
        Where the payload was injected: ``"body"``, ``"header"``, ``"url"``.
    inject_field:
        Parameter name or header name.
    expected_indicator:
        String or regex that should appear in the response if still vulnerable.
    is_regex:
        Whether *expected_indicator* is a regex.
    extra:
        Additional context (e.g. cloud resource ARN, model endpoint).
    """
    finding_id: str
    module: str
    target_url: str
    method: str = "GET"
    payload: str = ""
    inject_location: str = "body"
    inject_field: str = ""
    expected_indicator: str = ""
    is_regex: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "module": self.module,
            "target_url": self.target_url,
            "method": self.method,
            "payload": self.payload,
            "inject_location": self.inject_location,
            "inject_field": self.inject_field,
            "expected_indicator": self.expected_indicator,
            "is_regex": self.is_regex,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VerificationPath":
        return cls(
            finding_id=d.get("finding_id", ""),
            module=d.get("module", ""),
            target_url=d.get("target_url", ""),
            method=d.get("method", "GET"),
            payload=d.get("payload", ""),
            inject_location=d.get("inject_location", "body"),
            inject_field=d.get("inject_field", ""),
            expected_indicator=d.get("expected_indicator", ""),
            is_regex=d.get("is_regex", False),
            extra=d.get("extra", {}),
        )


@dataclass
class VerificationResult:
    """Result of a one-click verification run.

    Attributes
    ----------
    finding_id:
        The finding that was re-tested.
    status:
        ``"verified"`` — still vulnerable (patch NOT applied).
        ``"patched"`` — finding no longer reproducible.
        ``"inconclusive"`` — could not determine (network error, endpoint changed).
    evidence:
        Brief description of what was observed during the re-test.
    """
    finding_id: str
    status: str  # "verified" | "patched" | "inconclusive"
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "evidence": self.evidence,
        }


class VerificationRunner:
    """Store and re-execute finding verification paths.

    The path store lives in ``ScanContext.metadata["verification_paths"]``
    (a dict mapping ``finding_id → VerificationPath.to_dict()``).
    """

    def store(self, finding: Finding, path: VerificationPath, ctx: ScanContext) -> None:
        """Persist *path* in the scan context and in ``finding.raw``."""
        path_dict = path.to_dict()
        finding.raw["verification_path"] = path_dict
        ctx.metadata.setdefault("verification_paths", {})[finding.id] = path_dict
        logger.debug("Stored verification path for finding %s", finding.id)

    def store_from_finding(self, finding: Finding, ctx: ScanContext) -> None:
        """Extract and store a path that is already embedded in ``finding.raw``."""
        if "verification_path" in finding.raw:
            ctx.metadata.setdefault("verification_paths", {})[finding.id] = (
                finding.raw["verification_path"]
            )

    async def verify(
        self,
        finding_id: str,
        ctx: ScanContext,
    ) -> VerificationResult:
        """Re-execute the stored verification path for *finding_id*.

        Returns
        -------
        VerificationResult
            Status is ``"verified"`` if still vulnerable, ``"patched"`` if not,
            ``"inconclusive"`` if the re-test could not be completed.
        """
        paths: Dict[str, Any] = ctx.metadata.get("verification_paths", {})
        raw_path = paths.get(finding_id)

        if raw_path is None:
            return VerificationResult(
                finding_id=finding_id,
                status="inconclusive",
                evidence="No verification path stored for this finding.",
            )

        path = VerificationPath.from_dict(raw_path)

        # Use the shared HTTP client if available
        http_client = ctx.http_client
        if http_client is None:
            return VerificationResult(
                finding_id=finding_id,
                status="inconclusive",
                evidence="No HTTP client available in scan context.",
            )

        return await self._run_http_verification(path, http_client, finding_id)

    async def _run_http_verification(
        self,
        path: VerificationPath,
        client: Any,
        finding_id: str,
    ) -> VerificationResult:
        """Send the stored payload and check for the expected indicator."""
        import re

        try:
            url = path.target_url
            headers: Dict[str, str] = {}
            body: Optional[str] = None

            if path.inject_location == "header" and path.inject_field:
                headers[path.inject_field] = path.payload
            elif path.inject_location == "body" and path.inject_field:
                body = json.dumps({path.inject_field: path.payload})
                headers["Content-Type"] = "application/json"
            elif path.inject_location == "url":
                separator = "&" if "?" in url else "?"
                url = f"{url}{separator}{path.inject_field}={path.payload}"

            resp = await client.request(
                path.method, url,
                headers=headers,
                content=body,
            )
            response_text = getattr(resp, "text", "") or ""

            if path.expected_indicator:
                if path.is_regex:
                    matched = bool(re.search(path.expected_indicator, response_text, re.IGNORECASE))
                else:
                    matched = path.expected_indicator.lower() in response_text.lower()

                if matched:
                    return VerificationResult(
                        finding_id=finding_id,
                        status="verified",
                        evidence=(
                            f"Indicator {path.expected_indicator!r} found in response. "
                            f"Finding is still exploitable."
                        ),
                    )
                else:
                    return VerificationResult(
                        finding_id=finding_id,
                        status="patched",
                        evidence=(
                            f"Indicator {path.expected_indicator!r} NOT found in response. "
                            f"Finding appears to be remediated."
                        ),
                    )
            else:
                # No indicator — use status code as a heuristic
                status_code = getattr(resp, "status_code", 0)
                if status_code in (200, 201, 202):
                    return VerificationResult(
                        finding_id=finding_id,
                        status="inconclusive",
                        evidence=f"HTTP {status_code} — no indicator to confirm/deny. Manual review needed.",
                    )
                return VerificationResult(
                    finding_id=finding_id,
                    status="inconclusive",
                    evidence=f"HTTP {status_code} — inconclusive.",
                )

        except Exception as exc:
            logger.debug("Verification re-run failed for %s: %s", finding_id, exc)
            return VerificationResult(
                finding_id=finding_id,
                status="inconclusive",
                evidence=f"Re-test failed: {exc}",
            )
