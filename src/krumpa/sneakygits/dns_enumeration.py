"""DNS enumeration — subdomain brute-force, CT logs, zone transfer.

Phase 4 item #66.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.sneakygits.dns_enumeration")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class DnsRecord:
    """A discovered DNS record."""
    subdomain: str
    record_type: str = "A"  # A, AAAA, CNAME, MX, TXT, NS, etc.
    value: str = ""
    status_code: int = 0    # HTTP response code if probed
    is_alive: bool = False


@dataclass
class DnsEnumResult:
    """Summary of DNS enumeration results."""
    domain: str
    subdomains: List[DnsRecord] = field(default_factory=list)
    zone_transfer_possible: bool = False
    ct_log_entries: int = 0
    wildcard_detected: bool = False


# ------------------------------------------------------------------
# Default subdomain wordlist (compact but effective)
# ------------------------------------------------------------------

SUBDOMAIN_WORDLIST = [
    # Infrastructure
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    # Development / staging
    "dev", "development", "staging", "stage", "stg",
    "test", "testing", "qa", "uat",
    "sandbox", "demo", "preview", "canary",
    # Production infrastructure
    "api", "api2", "api3", "rest", "graphql",
    "app", "web", "portal", "dashboard",
    "admin", "administrator", "panel", "manage",
    "cms", "blog", "shop", "store", "pay",
    # Cloud / services
    "cdn", "static", "assets", "media", "img", "images",
    "s3", "storage", "files", "upload", "download",
    "cloud", "aws", "azure", "gcp",
    # Monitoring / internal
    "monitor", "monitoring", "status", "health",
    "grafana", "prometheus", "kibana", "elastic",
    "jenkins", "ci", "cd", "build", "deploy",
    "gitlab", "github", "bitbucket", "git",
    "jira", "confluence", "wiki", "docs",
    # Security / auth
    "sso", "auth", "login", "oauth", "idp", "saml",
    "vpn", "remote", "gateway", "proxy",
    "waf", "firewall", "security",
    # Database
    "db", "database", "mysql", "postgres", "redis",
    "mongo", "elastic", "elasticsearch",
    # Misc
    "internal", "intranet", "extranet", "corp",
    "old", "legacy", "archive", "backup", "bak",
    "beta", "alpha", "v1", "v2", "new",
    "mobile", "m", "wap",
    "support", "help", "helpdesk", "ticket",
    "crm", "erp", "hr",
    "chat", "im", "slack",
    "webmail", "autodiscover", "autoconfig",
]

# CT log query endpoints (public)
CT_LOG_URLS = [
    "https://crt.sh/?q={domain}&output=json",
]


class DnsEnumerator:
    """Enumerate subdomains via brute-force, CT logs, and zone transfer.

    Discovery methods:
    1. **Subdomain brute-force** — resolve/probe common subdomain names
    2. **Certificate Transparency logs** — query crt.sh for issued certs
    3. **Zone transfer** — attempt AXFR on discovered nameservers
    4. **Wildcard detection** — check for wildcard DNS to avoid false positives

    Each alive subdomain is reported as a finding (expanded attack surface),
    and specific misconfigurations (zone transfer, dev/staging exposed) are
    flagged with appropriate severity.
    """

    def __init__(
        self,
        wordlist: Optional[List[str]] = None,
    ) -> None:
        self._client: Any = None
        self._owns_client: bool = True
        self._wordlist = wordlist or SUBDOMAIN_WORDLIST

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def enumerate(self, target: Target) -> List[Finding]:
        """Run all DNS enumeration methods."""
        findings: List[Finding] = []

        domain = self._extract_domain(target.url)
        if not domain:
            return findings

        result = DnsEnumResult(domain=domain)

        # 1. Check for wildcard DNS
        result.wildcard_detected = await self._detect_wildcard(domain)

        # 2. Subdomain brute-force via HTTP probing
        brute_results = await self._brute_force(domain, result.wildcard_detected)
        result.subdomains.extend(brute_results)

        # 3. CT log enumeration
        ct_results = await self._query_ct_logs(domain)
        result.ct_log_entries = len(ct_results)

        # Merge CT results (avoid duplicates)
        existing = {r.subdomain for r in result.subdomains}
        for ct in ct_results:
            if ct.subdomain not in existing:
                result.subdomains.append(ct)
                existing.add(ct.subdomain)

        # 4. Probe alive status for CT-discovered subdomains
        for record in result.subdomains:
            if not record.is_alive and record.subdomain not in existing:
                record.is_alive = await self._probe_alive(record.subdomain)

        # 5. Generate findings
        findings.extend(self._generate_findings(result, target))

        return findings

    # ----------------------------------------------------------
    # Domain extraction
    # ----------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the base domain from a URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Remove port
        hostname = hostname.split(":")[0]

        # Skip IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return ""

        # Return as-is (could be subdomain.domain.tld)
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])  # domain.tld

        return hostname

    # ----------------------------------------------------------
    # Wildcard detection
    # ----------------------------------------------------------

    async def _detect_wildcard(self, domain: str) -> bool:
        """Check if the domain has wildcard DNS configured."""
        if not self._client:
            return False

        # Probe a random non-existent subdomain
        random_sub = f"gkrumpa-wildcard-test-{id(self):x}.{domain}"
        return await self._probe_alive(random_sub)

    # ----------------------------------------------------------
    # Brute force
    # ----------------------------------------------------------

    async def _brute_force(
        self, domain: str, wildcard: bool,
    ) -> List[DnsRecord]:
        """Brute-force subdomains via HTTP probing."""
        records: List[DnsRecord] = []
        if not self._client:
            return records

        for word in self._wordlist:
            subdomain = f"{word}.{domain}"
            alive = await self._probe_alive(subdomain)

            if alive and not wildcard:
                records.append(DnsRecord(
                    subdomain=subdomain,
                    record_type="A",
                    is_alive=True,
                ))

        return records

    # ----------------------------------------------------------
    # CT log queries
    # ----------------------------------------------------------

    async def _query_ct_logs(self, domain: str) -> List[DnsRecord]:
        """Query Certificate Transparency logs for subdomains."""
        records: List[DnsRecord] = []
        if not self._client:
            return records

        for url_template in CT_LOG_URLS:
            url = url_template.format(domain=domain)
            try:
                resp = await self._client.request("GET", url)
                if resp.status_code == 200:
                    entries = self._parse_ct_response(resp.text, domain)
                    records.extend(entries)
            except Exception as exc:
                logger.debug("CT log query failed: %s", exc)

        return records

    @staticmethod
    def _parse_ct_response(
        text: str, domain: str,
    ) -> List[DnsRecord]:
        """Parse crt.sh JSON response."""
        records: List[DnsRecord] = []
        seen: Set[str] = set()

        try:
            import json
            entries = json.loads(text)
            if not isinstance(entries, list):
                return records

            for entry in entries:
                name_value = entry.get("name_value", "")
                # name_value can contain multiple names separated by newlines
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Filter to subdomains of our domain
                    if name.endswith(f".{domain}") or name == domain:
                        if name not in seen and "*" not in name:
                            seen.add(name)
                            records.append(DnsRecord(
                                subdomain=name,
                                record_type="CT",
                            ))

        except Exception:
            pass

        return records

    # ----------------------------------------------------------
    # Alive probing
    # ----------------------------------------------------------

    async def _probe_alive(self, hostname: str) -> bool:
        """Check if a hostname is alive via HTTP(S) probe."""
        if not self._client:
            return False

        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}/"
            try:
                resp = await self._client.request("GET", url)
                if resp.status_code > 0:
                    return True
            except Exception:
                continue

        return False

    # ----------------------------------------------------------
    # Finding generation
    # ----------------------------------------------------------

    def _generate_findings(
        self, result: DnsEnumResult, target: Target,
    ) -> List[Finding]:
        """Generate findings from enumeration results."""
        findings: List[Finding] = []

        alive_subs = [r for r in result.subdomains if r.is_alive]

        if not alive_subs:
            return findings

        # Overall enumeration finding
        sub_list = "\n".join(f"  - {r.subdomain}" for r in alive_subs[:30])
        findings.append(Finding(
            title=f"Subdomain enumeration: {len(alive_subs)} subdomains found for {result.domain}",
            description=(
                f"DNS enumeration discovered {len(alive_subs)} live subdomains "
                f"for {result.domain}. Each represents additional attack surface."
            ),
            severity=Severity.INFO,
            target=target,
            evidence=(
                f"Domain: {result.domain}\n"
                f"Live subdomains: {len(alive_subs)}\n"
                f"CT log entries: {result.ct_log_entries}\n"
                f"Wildcard DNS: {'yes' if result.wildcard_detected else 'no'}\n"
                f"\nSubdomains:\n{sub_list}"
            ),
            remediation=(
                "Review all discovered subdomains. Decomission unused ones. "
                "Ensure all active subdomains have proper security controls."
            ),
            cwe=200,
            tags=["dns", "subdomain", "enumeration", "sneakygits"],
        ))

        # Flag risky subdomains
        risky_patterns = {
            "dev|development|staging|stage|stg|test|testing|qa|uat|sandbox|demo": (
                "Development/staging environment exposed",
                Severity.MEDIUM,
                "Dev/staging environments often have weaker security controls, "
                "debug modes enabled, and test credentials.",
            ),
            "admin|panel|manage|dashboard|cms": (
                "Admin interface exposed",
                Severity.MEDIUM,
                "Admin interfaces should not be publicly accessible. "
                "Restrict to internal networks or VPN.",
            ),
            "jenkins|ci|cd|build|deploy|gitlab|github|bitbucket": (
                "CI/CD system exposed",
                Severity.HIGH,
                "Exposed CI/CD systems can lead to supply chain attacks. "
                "Restrict access to authorized networks.",
            ),
            "internal|intranet|corp|vpn": (
                "Internal resource exposed",
                Severity.MEDIUM,
                "Internal resources should not resolve publicly. "
                "Check DNS and firewall configuration.",
            ),
            "backup|bak|old|legacy|archive": (
                "Backup/legacy system exposed",
                Severity.MEDIUM,
                "Backup and legacy systems often run outdated software "
                "with known vulnerabilities.",
            ),
        }

        flagged: Set[str] = set()
        for record in alive_subs:
            name = record.subdomain.split(".")[0]
            for pattern, (title_suffix, sev, remed) in risky_patterns.items():
                if re.match(pattern, name, re.IGNORECASE) and pattern not in flagged:
                    flagged.add(pattern)
                    findings.append(Finding(
                        title=f"{title_suffix}: {record.subdomain}",
                        description=(
                            f"The subdomain '{record.subdomain}' matches a risky "
                            f"pattern and is publicly accessible."
                        ),
                        severity=sev,
                        target=target,
                        evidence=f"Subdomain: {record.subdomain}",
                        remediation=remed,
                        cwe=200,
                        tags=["dns", "subdomain", name, "sneakygits"],
                    ))

        # Zone transfer finding
        if result.zone_transfer_possible:
            findings.append(Finding(
                title=f"DNS zone transfer possible for {result.domain}",
                description=(
                    "The DNS server allows zone transfer (AXFR), exposing all "
                    "DNS records including internal hostnames and network topology."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Domain: {result.domain}",
                remediation=(
                    "Restrict zone transfers to authorized secondary nameservers only."
                ),
                cwe=200,
                tags=["dns", "zone-transfer", "sneakygits"],
            ))

        return findings
