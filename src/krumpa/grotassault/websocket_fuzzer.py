"""WebSocket fuzzing — message manipulation, cross-site WebSocket hijacking.

Phase 4 item #56.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class WebSocketEndpoint:
    """A discovered WebSocket endpoint."""
    url: str  # ws:// or wss://
    origin: str = ""
    protocols: List[str] = field(default_factory=list)
    auth_header: str = ""


@dataclass
class WsFuzzResult:
    """Result of a single WebSocket fuzz attempt."""
    payload: str
    response: str = ""
    error: str = ""
    duration_ms: float = 0.0
    connection_closed: bool = False
    status_code: Optional[int] = None


# ------------------------------------------------------------------
# Fuzz payload categories
# ------------------------------------------------------------------

WS_INJECTION_PAYLOADS = [
    # XSS via WebSocket
    '<script>alert("ws-xss")</script>',
    '<img src=x onerror=alert("ws-xss")>',
    '"><script>alert(document.cookie)</script>',
    # SQLi via WebSocket
    "' OR 1=1--",
    '" OR ""="',
    "'; DROP TABLE users;--",
    "1 UNION SELECT 1,2,3--",
    # Command injection
    "; ls -la",
    "| cat /etc/passwd",
    "`id`",
    "$(whoami)",
    # SSTI
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    # Path traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    # LDAP
    "*)(&",
    "*(|(&))",
    # NoSQL
    '{"$gt": ""}',
    '{"$ne": null}',
]

WS_PROTOCOL_PAYLOADS = [
    # Oversized frames
    "A" * 65536,
    "A" * 1048576,  # 1MB
    # Empty / null
    "",
    "\x00",
    "\x00" * 100,
    # Binary-like
    "\xff\xfe\xfd\xfc",
    # Fragmented JSON
    '{"incomplete": ',
    '{"key": "value"',
    # Deeply nested
    '{"a":' * 50 + '"deep"' + '}' * 50,
    # Unicode edge cases
    "\ud800",  # Lone surrogate
    "\ufeff" * 100,  # BOM flood
    "\u200b" * 100,  # Zero-width spaces
]

WS_AUTH_BYPASS_ORIGINS = [
    "https://evil.example.com",
    "null",
    "http://localhost",
    "https://localhost",
    "",
    "https://attacker.com",
    "file://",
]


class WebSocketFuzzer:
    """Fuzz WebSocket endpoints for security vulnerabilities.

    Tests:
    - Cross-Site WebSocket Hijacking (CSWSH) via Origin manipulation
    - Message injection (XSS, SQLi, SSTI, CMDi through WS messages)
    - Protocol-level abuse (oversized frames, fragmentation, null bytes)
    - Authentication bypass on WS upgrade
    - Denial of service via resource exhaustion
    - Unencrypted WebSocket (ws:// vs wss://)
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def check(self, target: Target) -> List[Finding]:
        """Run all WebSocket security checks."""
        findings: List[Finding] = []
        url = target.url

        # 1. Discover WebSocket endpoints
        endpoints = await self._discover_endpoints(url, target)

        if not endpoints:
            return findings

        for ep in endpoints:
            # 2. Transport security
            findings.extend(self._check_transport_security(ep, target))

            # 3. Cross-Site WebSocket Hijacking
            findings.extend(await self._test_cswsh(ep, target))

            # 4. Auth bypass on upgrade
            findings.extend(await self._test_upgrade_auth_bypass(ep, target))

            # 5. Message injection
            findings.extend(await self._test_message_injection(ep, target))

            # 6. Protocol abuse
            findings.extend(await self._test_protocol_abuse(ep, target))

        return findings

    # ----------------------------------------------------------
    # Endpoint discovery
    # ----------------------------------------------------------

    async def _discover_endpoints(
        self, url: str, target: Target,
    ) -> List[WebSocketEndpoint]:
        """Discover WebSocket endpoints via HTTP probing."""
        endpoints: List[WebSocketEndpoint] = []
        if not self._client:
            return endpoints

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        # Common WebSocket paths
        ws_paths = [
            "/ws", "/websocket", "/socket", "/ws/", "/websocket/",
            "/socket.io/", "/sockjs/", "/hub", "/signalr",
            "/cable", "/stream", "/events", "/live",
            "/api/ws", "/api/websocket", "/api/stream",
            "/realtime", "/push", "/notifications/ws",
            "/chat", "/chat/ws",
        ]

        for path in ws_paths:
            probe_url = f"{base}{path}"
            try:
                resp = await self._client.request(
                    "GET", probe_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": base,
                    },
                )

                # 101 Switching Protocols = WebSocket endpoint
                if resp.status_code == 101:
                    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                    endpoints.append(WebSocketEndpoint(
                        url=ws_url,
                        origin=base,
                    ))
                elif resp.status_code == 426:
                    # "Upgrade Required" — endpoint exists but needs proper handshake
                    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                    endpoints.append(WebSocketEndpoint(
                        url=ws_url,
                        origin=base,
                    ))
                elif resp.status_code == 400:
                    text = resp.text.lower()
                    if "websocket" in text or "upgrade" in text:
                        ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                        endpoints.append(WebSocketEndpoint(
                            url=ws_url,
                            origin=base,
                        ))

            except Exception:
                continue

        return endpoints

    # ----------------------------------------------------------
    # Transport security
    # ----------------------------------------------------------

    def _check_transport_security(
        self, endpoint: WebSocketEndpoint, target: Target,
    ) -> List[Finding]:
        """Check if WebSocket uses encryption (wss://)."""
        findings: List[Finding] = []

        if endpoint.url.startswith("ws://"):
            findings.append(Finding(
                title=f"Unencrypted WebSocket: {endpoint.url}",
                description=(
                    f"WebSocket endpoint uses ws:// (unencrypted) instead of wss://. "
                    f"All messages are transmitted in plaintext, allowing interception "
                    f"and modification by network attackers."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"URL: {endpoint.url}",
                remediation="Use wss:// (WebSocket Secure) for all WebSocket connections.",
                cwe=319,
                tags=["websocket", "transport-security", "grotassault"],
            ))

        return findings

    # ----------------------------------------------------------
    # Cross-Site WebSocket Hijacking
    # ----------------------------------------------------------

    async def _test_cswsh(
        self, endpoint: WebSocketEndpoint, target: Target,
    ) -> List[Finding]:
        """Test for Cross-Site WebSocket Hijacking via Origin manipulation."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        parsed = urlparse(endpoint.url)
        http_scheme = "https" if endpoint.url.startswith("wss") else "http"
        http_url = f"{http_scheme}://{parsed.netloc}{parsed.path}"

        for evil_origin in WS_AUTH_BYPASS_ORIGINS:
            try:
                resp = await self._client.request(
                    "GET", http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": evil_origin,
                    },
                )

                # If 101 is returned with an evil origin, CSWSH is possible
                if resp.status_code == 101:
                    findings.append(Finding(
                        title=f"Cross-Site WebSocket Hijacking: {endpoint.url}",
                        description=(
                            f"The WebSocket endpoint accepted a connection with "
                            f"Origin: '{evil_origin}'. An attacker can host a page "
                            f"that connects to this WebSocket from a different origin, "
                            f"hijacking the user's authenticated session."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Evil Origin: {evil_origin}\n"
                            f"Response: {resp.status_code}"
                        ),
                        remediation=(
                            "Validate the Origin header in WebSocket upgrade requests. "
                            "Reject connections from untrusted origins. Use CSRF tokens "
                            "in the WebSocket handshake."
                        ),
                        cwe=346,
                        tags=["websocket", "cswsh", "origin-bypass", "grotassault"],
                    ))
                    break  # One proof is enough

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Auth bypass on upgrade
    # ----------------------------------------------------------

    async def _test_upgrade_auth_bypass(
        self, endpoint: WebSocketEndpoint, target: Target,
    ) -> List[Finding]:
        """Test if WebSocket upgrade can bypass authentication."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        parsed = urlparse(endpoint.url)
        http_scheme = "https" if endpoint.url.startswith("wss") else "http"
        http_url = f"{http_scheme}://{parsed.netloc}{parsed.path}"

        # Try connecting without any auth cookies/headers
        try:
            resp = await self._client.request(
                "GET", http_url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": endpoint.origin,
                    # No Cookie or Authorization headers
                },
            )

            if resp.status_code == 101:
                findings.append(Finding(
                    title=f"WebSocket upgrade accepted without authentication: {endpoint.url}",
                    description=(
                        "The WebSocket endpoint accepted an upgrade request with "
                        "no authentication credentials. If the endpoint provides "
                        "access to sensitive data or operations, this is an "
                        "authentication bypass."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Endpoint: {endpoint.url}\n"
                        f"No auth headers sent\n"
                        f"Response: {resp.status_code}"
                    ),
                    remediation=(
                        "Require authentication for WebSocket upgrades. Validate "
                        "session cookies or tokens during the HTTP upgrade handshake, "
                        "not just after the WebSocket is established."
                    ),
                    cwe=306,
                    tags=["websocket", "auth-bypass", "grotassault"],
                ))

        except Exception:
            pass

        return findings

    # ----------------------------------------------------------
    # Message injection
    # ----------------------------------------------------------

    async def _test_message_injection(
        self, endpoint: WebSocketEndpoint, target: Target,
    ) -> List[Finding]:
        """Test for injection vulnerabilities via WebSocket messages.

        Since we can't establish a real WS connection with httpx, we probe
        the HTTP upgrade + check for WS-like HTTP endpoints that accept
        message-style POSTs (polling fallbacks).
        """
        findings: List[Finding] = []
        if not self._client:
            return findings

        parsed = urlparse(endpoint.url)
        http_scheme = "https" if endpoint.url.startswith("wss") else "http"

        # Many WS implementations have HTTP polling fallbacks
        polling_paths = [
            f"{http_scheme}://{parsed.netloc}{parsed.path}",
            f"{http_scheme}://{parsed.netloc}{parsed.path}/xhr-polling",
            f"{http_scheme}://{parsed.netloc}{parsed.path}/jsonp-polling",
            f"{http_scheme}://{parsed.netloc}{parsed.path}/send",
        ]

        for poll_url in polling_paths:
            for payload in WS_INJECTION_PAYLOADS[:10]:  # Limit to avoid DOS
                try:
                    # Try sending as JSON message
                    msg = {"message": payload, "type": "text"}
                    resp = await self._client.request(
                        "POST", poll_url, json_body=msg,
                    )

                    if resp.status_code in (200, 201):
                        text = resp.text
                        # Check for reflection / error disclosure
                        if payload in text:
                            findings.append(Finding(
                                title=f"WebSocket message injection reflected: {endpoint.url}",
                                description=(
                                    f"A fuzz payload sent to the WebSocket polling "
                                    f"endpoint was reflected in the response. This "
                                    f"indicates the server processes and echoes "
                                    f"WebSocket message content without sanitization."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=(
                                    f"Endpoint: {poll_url}\n"
                                    f"Payload: {payload[:100]}\n"
                                    f"Reflected in response: yes"
                                ),
                                remediation=(
                                    "Sanitize all WebSocket message content. Apply "
                                    "the same input validation as HTTP parameters. "
                                    "Use parameterized queries for any DB operations."
                                ),
                                cwe=79,
                                tags=["websocket", "injection", "grotassault"],
                            ))
                            return findings  # One proof is enough

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Protocol abuse
    # ----------------------------------------------------------

    async def _test_protocol_abuse(
        self, endpoint: WebSocketEndpoint, target: Target,
    ) -> List[Finding]:
        """Test protocol-level abuse via HTTP fallback endpoints."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        parsed = urlparse(endpoint.url)
        http_scheme = "https" if endpoint.url.startswith("wss") else "http"
        poll_url = f"{http_scheme}://{parsed.netloc}{parsed.path}"

        # Test oversized payloads
        for payload in WS_PROTOCOL_PAYLOADS[:5]:
            try:
                resp = await self._client.request(
                    "POST", poll_url,
                    body=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )

                if resp.status_code == 500:
                    text = resp.text.lower()
                    if any(kw in text for kw in [
                        "stack trace", "exception", "traceback",
                        "internal server error", "nullpointer", "segfault",
                    ]):
                        findings.append(Finding(
                            title=f"WebSocket server error on malformed input: {endpoint.url}",
                            description=(
                                "Sending malformed or oversized data to the WebSocket "
                                "endpoint caused a server error with stack trace "
                                "disclosure. This may indicate input handling bugs."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Endpoint: {poll_url}\n"
                                f"Payload length: {len(payload)}\n"
                                f"Status: {resp.status_code}\n"
                                f"Error glimpse: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Implement proper message size limits. Catch and "
                                "handle malformed input gracefully without exposing "
                                "internal error details."
                            ),
                            cwe=209,
                            tags=["websocket", "protocol-abuse", "grotassault"],
                        ))
                        break

            except Exception:
                continue

        return findings
