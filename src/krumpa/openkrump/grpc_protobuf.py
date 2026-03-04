"""gRPC / Protobuf support — reflection-based discovery, schema validation.

Phase 4 item #58.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, List
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.grpc_protobuf")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class GrpcService:
    """A discovered gRPC service."""
    name: str
    methods: List[GrpcMethod] = field(default_factory=list)
    package: str = ""


@dataclass
class GrpcMethod:
    """A gRPC method descriptor."""
    name: str
    service: str
    input_type: str = ""
    output_type: str = ""
    client_streaming: bool = False
    server_streaming: bool = False
    full_name: str = ""


@dataclass
class ProtobufField:
    """A field in a protobuf message."""
    number: int
    name: str
    type_name: str = ""
    label: str = ""  # OPTIONAL, REQUIRED, REPEATED
    default_value: str = ""


# ------------------------------------------------------------------
# gRPC content type markers
# ------------------------------------------------------------------

GRPC_CONTENT_TYPES = [
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web-text",
    "application/grpc-web-text+proto",
]

# gRPC reflection service method
REFLECTION_PATH = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
REFLECTION_V1_PATH = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"

# Common gRPC health check
HEALTH_PATH = "/grpc.health.v1.Health/Check"


class GrpcProtobufAnalyzer:
    """Analyze gRPC services for security issues.

    Tests:
    - gRPC reflection endpoint exposure (service enumeration)
    - Unauthenticated method invocation
    - Input validation on protobuf fields
    - gRPC-Web exposure and misconfiguration
    - Health endpoint information disclosure
    - Missing TLS on gRPC channels
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all gRPC/Protobuf security checks."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        url = target.url
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Detect gRPC endpoints
        is_grpc = await self._detect_grpc(base, target)

        if not is_grpc:
            # Try gRPC-Web detection
            is_grpc = await self._detect_grpc_web(base, target)

        if not is_grpc:
            return findings

        # 2. Check reflection exposure
        ref_findings, services = await self._check_reflection(base, target)
        findings.extend(ref_findings)

        # 3. Check health endpoint
        findings.extend(await self._check_health_endpoint(base, target))

        # 4. Check transport security
        findings.extend(self._check_transport_security(url, target))

        # 5. Test unauthenticated access
        findings.extend(await self._test_unauth_access(base, services, target))

        # 6. Test input validation
        findings.extend(await self._test_input_validation(base, services, target))

        return findings

    # ----------------------------------------------------------
    # gRPC detection
    # ----------------------------------------------------------

    async def _detect_grpc(self, base: str, target: Target) -> bool:
        """Detect if the server speaks gRPC."""
        try:
            resp = await self._client.request(
                "POST", f"{base}/",
                headers={
                    "Content-Type": "application/grpc",
                    "TE": "trailers",
                },
                body=b"\x00\x00\x00\x00\x00",  # Empty gRPC frame
            )
            ct = resp.headers.get("content-type", "")
            if any(g in ct for g in GRPC_CONTENT_TYPES):
                return True
            # gRPC servers often return specific error codes
            if resp.status_code == 415 and "grpc" in resp.text.lower():
                return True
        except Exception:
            pass
        return False

    async def _detect_grpc_web(self, base: str, target: Target) -> bool:
        """Detect gRPC-Web proxy."""
        try:
            resp = await self._client.request(
                "POST", f"{base}/",
                headers={
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1",
                },
                body=b"\x00\x00\x00\x00\x00",
            )
            ct = resp.headers.get("content-type", "")
            if "grpc-web" in ct:
                return True
        except Exception:
            pass
        return False

    # ----------------------------------------------------------
    # Reflection check
    # ----------------------------------------------------------

    async def _check_reflection(
        self, base: str, target: Target,
    ) -> tuple[List[Finding], List[GrpcService]]:
        """Check if gRPC reflection is enabled (allows service enumeration)."""
        findings: List[Finding] = []
        services: List[GrpcService] = []

        for ref_path in [REFLECTION_PATH, REFLECTION_V1_PATH]:
            try:
                # Build a "list services" reflection request
                # Field 3 = list_services (string "")
                payload = self._build_grpc_frame(b"\x1a\x00")

                resp = await self._client.request(
                    "POST", f"{base}{ref_path}",
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                    },
                    body=payload,
                )

                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "grpc" in ct:
                        # Reflection is enabled — extract service names
                        service_names = self._parse_reflection_response(resp.content)
                        for name in service_names:
                            services.append(GrpcService(name=name))

                        findings.append(Finding(
                            title="gRPC reflection enabled — service enumeration possible",
                            description=(
                                "The gRPC server has the reflection service enabled, "
                                "allowing attackers to enumerate all available services, "
                                "methods, and message types without prior knowledge."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Reflection endpoint: {base}{ref_path}\n"
                                f"Discovered services: {', '.join(service_names) or 'response received'}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Disable gRPC reflection in production environments. "
                                "If reflection is required for development, restrict "
                                "access via network policies or authentication."
                            ),
                            cwe=200,
                            tags=["grpc", "reflection", "enumeration", "openkrump"],
                        ))
                        break

            except Exception:
                continue

        return findings, services

    # ----------------------------------------------------------
    # Health endpoint
    # ----------------------------------------------------------

    async def _check_health_endpoint(
        self, base: str, target: Target,
    ) -> List[Finding]:
        """Check for exposed gRPC health endpoint."""
        findings: List[Finding] = []

        try:
            payload = self._build_grpc_frame(b"")
            resp = await self._client.request(
                "POST", f"{base}{HEALTH_PATH}",
                headers={
                    "Content-Type": "application/grpc",
                    "TE": "trailers",
                },
                body=payload,
            )

            if resp.status_code == 200:
                findings.append(Finding(
                    title="gRPC health endpoint exposed",
                    description=(
                        "The gRPC health check endpoint is publicly accessible. "
                        "While health checks are common, they can reveal service "
                        "status and naming information."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=(
                        f"Endpoint: {base}{HEALTH_PATH}\n"
                        f"Status: {resp.status_code}\n"
                        f"Response size: {len(resp.content)} bytes"
                    ),
                    remediation=(
                        "Restrict health endpoints to internal networks or "
                        "authenticated callers if they expose service details."
                    ),
                    cwe=200,
                    tags=["grpc", "health", "info-disclosure", "openkrump"],
                ))

        except Exception:
            pass

        return findings

    # ----------------------------------------------------------
    # Transport security
    # ----------------------------------------------------------

    def _check_transport_security(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Check if gRPC uses TLS."""
        findings: List[Finding] = []

        if url.startswith("http://"):
            findings.append(Finding(
                title="gRPC service without TLS",
                description=(
                    "The gRPC endpoint is accessible over plaintext HTTP. "
                    "All RPC calls including authentication credentials are "
                    "transmitted unencrypted."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"URL: {url} (HTTP, not HTTPS)",
                remediation=(
                    "Configure TLS for all gRPC channels. Use mutual TLS "
                    "(mTLS) for service-to-service communication."
                ),
                cwe=319,
                tags=["grpc", "tls", "transport-security", "openkrump"],
            ))

        return findings

    # ----------------------------------------------------------
    # Unauthenticated access
    # ----------------------------------------------------------

    async def _test_unauth_access(
        self, base: str, services: List[GrpcService],
        target: Target,
    ) -> List[Finding]:
        """Test if gRPC methods can be invoked without authentication."""
        findings: List[Finding] = []
        if not services:
            return findings

        for svc in services:
            if "reflection" in svc.name.lower() or "health" in svc.name.lower():
                continue  # Skip utility services

            # Try invoking a method without auth
            # Build empty call to /{package}.{service}/{method}
            method_path = f"/{svc.name}/UnknownMethod"
            try:
                payload = self._build_grpc_frame(b"")
                resp = await self._client.request(
                    "POST", f"{base}{method_path}",
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                    },
                    body=payload,
                )

                # grpc-status: 12 = UNIMPLEMENTED (method exists but unknown)
                # grpc-status: 16 = UNAUTHENTICATED
                # grpc-status: 7 = PERMISSION_DENIED
                grpc_status = resp.headers.get("grpc-status", "")

                if grpc_status in ("12", "0"):
                    # Service reached without auth — either unimplemented
                    # or succeeded (both indicate no auth wall)
                    findings.append(Finding(
                        title=f"gRPC service accessible without authentication: {svc.name}",
                        description=(
                            f"The gRPC service '{svc.name}' accepted a request "
                            f"without authentication credentials. The server "
                            f"responded with gRPC status {grpc_status} instead "
                            f"of UNAUTHENTICATED (16)."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Service: {svc.name}\n"
                            f"Path: {method_path}\n"
                            f"gRPC status: {grpc_status}\n"
                            f"HTTP status: {resp.status_code}"
                        ),
                        remediation=(
                            "Require authentication for all gRPC services. Use "
                            "gRPC interceptors to validate tokens/credentials "
                            "before processing any RPC."
                        ),
                        cwe=306,
                        tags=["grpc", "auth", "unauthenticated", "openkrump"],
                    ))

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Input validation
    # ----------------------------------------------------------

    async def _test_input_validation(
        self, base: str, services: List[GrpcService],
        target: Target,
    ) -> List[Finding]:
        """Test input validation on gRPC methods."""
        findings: List[Finding] = []

        # Malformed protobuf payloads
        malformed_payloads = [
            # Truncated varint
            b"\x08\xff\xff\xff\xff",
            # Invalid wire type
            b"\x07\x00",
            # Extremely large length-delimited field
            b"\x0a\xff\xff\xff\xff\x0f" + b"A" * 100,
            # Nested depth bomb
            b"\x0a\x02" * 50 + b"\x08\x01",
            # Negative varint (zigzag encoding)
            b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
            # String with null bytes
            b"\x0a\x05he\x00lo",
        ]

        for svc in services[:3]:  # Limit probing
            if "reflection" in svc.name.lower():
                continue

            method_path = f"/{svc.name}/UnknownMethod"

            for payload_bytes in malformed_payloads:
                try:
                    frame = self._build_grpc_frame(payload_bytes)
                    resp = await self._client.request(
                        "POST", f"{base}{method_path}",
                        headers={
                            "Content-Type": "application/grpc",
                            "TE": "trailers",
                        },
                        body=frame,
                    )

                    if resp.status_code == 500:
                        text = resp.text.lower()
                        if any(kw in text for kw in [
                            "exception", "stack", "traceback",
                            "panic", "segfault",
                        ]):
                            findings.append(Finding(
                                title=f"gRPC server error on malformed protobuf: {svc.name}",
                                description=(
                                    "Sending malformed protobuf data caused a "
                                    "server error with potential information "
                                    "disclosure. The server does not properly "
                                    "validate protobuf message structure."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Service: {svc.name}\n"
                                    f"Payload (hex): {payload_bytes.hex()[:60]}\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Error: {resp.text[:200]}"
                                ),
                                remediation=(
                                    "Validate all incoming protobuf messages. "
                                    "Use well-typed message definitions and "
                                    "handle parse errors gracefully."
                                ),
                                cwe=20,
                                tags=["grpc", "protobuf", "input-validation", "openkrump"],
                            ))
                            break  # One proof per service

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    @staticmethod
    def _build_grpc_frame(data: bytes) -> bytes:
        """Build a gRPC length-prefixed frame.

        Format: [compressed:1byte][length:4bytes][data:N bytes]
        """
        return b"\x00" + struct.pack(">I", len(data)) + data

    @staticmethod
    def _parse_reflection_response(data: bytes) -> List[str]:
        """Extract service names from a reflection response (best-effort)."""
        services: List[str] = []
        # Simple heuristic: look for ASCII service name patterns in response
        try:
            text = data.decode("utf-8", errors="replace")
            # Service names look like "fully.qualified.ServiceName"
            matches = re.findall(r'([a-zA-Z][a-zA-Z0-9_.]+\.[A-Z][a-zA-Z0-9]+)', text)
            for m in matches:
                if m not in services and "grpc.reflection" not in m.lower():
                    services.append(m)
        except Exception:
            pass
        return services
