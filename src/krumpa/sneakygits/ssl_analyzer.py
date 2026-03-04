"""
SneakyGits — SSL/TLS analysis.

Evaluate protocol versions, cipher suites, certificate validity,
and HSTS configuration of HTTPS targets.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.ssl_analyzer")


# ------------------------------------------------------------------
# Weak cipher / protocol definitions
# ------------------------------------------------------------------

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED",
}

# Perfect forward secrecy indicators
PFS_CIPHERS = {"ECDHE", "DHE", "ECDH"}


@dataclass
class TlsInfo(HttpClientMixin):
    """Collected TLS information for a target."""
    hostname: str = ""
    port: int = 443
    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    cert_subject: Dict[str, str] = field(default_factory=dict)
    cert_issuer: Dict[str, str] = field(default_factory=dict)
    cert_not_before: Optional[datetime] = None
    cert_not_after: Optional[datetime] = None
    cert_san: List[str] = field(default_factory=list)
    hsts_header: str = ""
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    has_pfs: bool = False
    errors: List[str] = field(default_factory=list)


class SslAnalyzer(HttpClientMixin):
    """
    Analyse the SSL/TLS configuration of HTTPS targets.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        check_hsts: bool = True,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._check_hsts = check_hsts

    async def analyze(self, target: Target) -> List[Finding]:
        """Perform TLS analysis on *target* and return findings."""
        findings: List[Finding] = []

        parsed = urlparse(target.url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme != "https":
            findings.append(Finding(
                title="HTTP used instead of HTTPS",
                description=f"Target {target.url} uses plain HTTP — all data in transit is unencrypted.",
                severity=Severity.HIGH,
                target=target,
                remediation="Redirect all HTTP traffic to HTTPS. Obtain a TLS certificate (e.g. Let's Encrypt).",
                cwe=319,
                tags=["ssl", "tls", "transport"],
            ))
            return findings

        info = self._get_tls_info(hostname, port)

        # Check HSTS via HTTP if configured
        if self._check_hsts:
            await self._check_hsts_header(target, info)

        findings.extend(self._evaluate(info, target))
        return findings

    def analyze_info(self, info: TlsInfo, target: Target) -> List[Finding]:
        """Evaluate a pre-populated TlsInfo (useful in tests)."""
        return self._evaluate(info, target)

    # ------------------------------------------------------------------
    # TLS information gathering
    # ------------------------------------------------------------------

    def _get_tls_info(self, hostname: str, port: int) -> TlsInfo:
        """Connect with ssl and extract cert / cipher info."""
        info = TlsInfo(hostname=hostname, port=port)

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((hostname, port), timeout=10),
                server_hostname=hostname,
            ) as sock:
                # Protocol + cipher
                cipher = sock.cipher()
                if cipher:
                    info.cipher_name = cipher[0]
                    info.protocol_version = cipher[1]
                    info.cipher_bits = cipher[2]

                # PFS check
                info.has_pfs = any(kw in info.cipher_name for kw in PFS_CIPHERS)

                # Certificate
                cert = sock.getpeercert()
                if cert:
                    info.cert_subject = self._parse_dn(cert.get("subject", ()))
                    info.cert_issuer = self._parse_dn(cert.get("issuer", ()))
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    info.cert_not_before = self._parse_cert_date(
                        str(not_before) if not_before is not None else None
                    )
                    info.cert_not_after = self._parse_cert_date(
                        str(not_after) if not_after is not None else None
                    )
                    san_entries: list[str] = [
                        str(v) for t, v in cert.get("subjectAltName", ())
                        if t == "DNS"
                    ]
                    info.cert_san = san_entries

        except ssl.SSLCertVerificationError as exc:
            info.errors.append(f"Certificate verification failed: {exc}")
        except ssl.SSLError as exc:
            info.errors.append(f"SSL error: {exc}")
        except OSError as exc:
            info.errors.append(f"Connection error: {exc}")

        return info

    async def _check_hsts_header(self, target: Target, info: TlsInfo) -> None:
        """Fetch target and inspect Strict-Transport-Security header."""
        client = self._get_client()
        try:
            resp = await client.request("GET", target.url)
            headers = getattr(resp, "headers", {})
            hsts = headers.get("strict-transport-security", headers.get("Strict-Transport-Security", ""))
            info.hsts_header = hsts

            if hsts:
                m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                if m:
                    info.hsts_max_age = int(m.group(1))
                info.hsts_include_subdomains = "includesubdomains" in hsts.lower()
                info.hsts_preload = "preload" in hsts.lower()
        except Exception as exc:
            logger.debug("Failed to check HSTS: %s", exc)
        finally:
            self._maybe_close(client)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, info: TlsInfo, target: Target) -> List[Finding]:
        findings: List[Finding] = []

        # Protocol version
        if info.protocol_version in WEAK_PROTOCOLS:
            findings.append(Finding(
                title=f"Weak TLS protocol: {info.protocol_version}",
                description=f"Server supports {info.protocol_version} which has known vulnerabilities.",
                severity=Severity.HIGH,
                target=target,
                evidence=f"Protocol: {info.protocol_version}, cipher: {info.cipher_name}",
                remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                cwe=326,
                tags=["ssl", "tls", "protocol"],
            ))

        # Weak cipher
        if info.cipher_name:
            for weak in WEAK_CIPHERS:
                if weak.upper() in info.cipher_name.upper():
                    findings.append(Finding(
                        title=f"Weak cipher suite: {info.cipher_name}",
                        description=f"Cipher {info.cipher_name} uses weak algorithm ({weak}).",
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Cipher: {info.cipher_name}, bits: {info.cipher_bits}",
                        remediation="Configure server to prefer AEAD ciphers (AES-GCM, ChaCha20).",
                        cwe=327,
                        tags=["ssl", "tls", "cipher"],
                    ))
                    break

        # No PFS
        if info.cipher_name and not info.has_pfs:
            findings.append(Finding(
                title="No perfect forward secrecy (PFS)",
                description=f"Cipher {info.cipher_name} does not provide PFS.",
                severity=Severity.LOW,
                target=target,
                remediation="Prefer ECDHE or DHE cipher suites for forward secrecy.",
                cwe=326,
                tags=["ssl", "tls", "pfs"],
            ))

        # Certificate expiry
        now = datetime.now(timezone.utc)
        if info.cert_not_after:
            days_left = (info.cert_not_after - now).days
            if days_left < 0:
                findings.append(Finding(
                    title="SSL certificate expired",
                    description=f"Certificate expired {abs(days_left)} days ago ({info.cert_not_after.isoformat()}).",
                    severity=Severity.CRITICAL,
                    target=target,
                    cwe=295,
                    tags=["ssl", "certificate", "expired"],
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title=f"SSL certificate expiring soon ({days_left} days)",
                    description=f"Certificate expires on {info.cert_not_after.isoformat()}.",
                    severity=Severity.MEDIUM,
                    target=target,
                    cwe=295,
                    tags=["ssl", "certificate", "expiring"],
                ))

        # Certificate errors
        for err in info.errors:
            findings.append(Finding(
                title="SSL/TLS error",
                description=err,
                severity=Severity.HIGH if "verification" in err.lower() else Severity.MEDIUM,
                target=target,
                cwe=295,
                tags=["ssl", "tls", "error"],
            ))

        # HSTS evaluation
        if not info.hsts_header:
            findings.append(Finding(
                title="Missing HSTS header",
                description="Strict-Transport-Security header not found.",
                severity=Severity.MEDIUM,
                target=target,
                remediation="Add Strict-Transport-Security header with max-age ≥ 31536000.",
                cwe=523,
                tags=["ssl", "hsts", "header"],
            ))
        elif info.hsts_max_age < 31536000:
            findings.append(Finding(
                title=f"HSTS max-age too short ({info.hsts_max_age}s)",
                description=f"HSTS max-age is {info.hsts_max_age}s, should be ≥ 31536000 (1 year).",
                severity=Severity.LOW,
                target=target,
                cwe=523,
                tags=["ssl", "hsts", "header"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_dn(dn_tuple: Any) -> Dict[str, str]:
        result: Dict[str, str] = {}
        if isinstance(dn_tuple, tuple):
            for rdn in dn_tuple:
                if isinstance(rdn, tuple):
                    for attr, val in rdn:
                        result[attr] = val
        return result

    @staticmethod
    def _parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
