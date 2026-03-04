"""
SneakyGits — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import List

from krumpa.core import BaseModule, Finding, ScanContext, Severity, Target
from krumpa.sneakygits.crawler import Crawler
from krumpa.sneakygits.fingerprint import Fingerprinter
from krumpa.sneakygits.header_audit import HeaderAuditor
from krumpa.sneakygits.cors_checker import CorsChecker
from krumpa.sneakygits.content_discovery import ContentDiscovery
from krumpa.sneakygits.js_extractor import JsExtractor
from krumpa.sneakygits.ssl_analyzer import SslAnalyzer
from krumpa.sneakygits.waf_detector import WafDetector
from krumpa.sneakygits.backup_scanner import BackupScanner
from krumpa.sneakygits.fingerprint_db import FingerprintDb
from krumpa.sneakygits.method_discovery import MethodDiscovery
from krumpa.sneakygits.info_leakage import InfoLeakageScanner
from krumpa.sneakygits.dns_enumeration import DnsEnumerator

logger = logging.getLogger("krumpa.sneakygits")


class SneakyGitsModule(BaseModule):
    """Recon & target enumeration."""

    name = "SneakyGits"
    description = "Reconnaissance — crawl, enumerate, fingerprint"
    dependencies: List[str] = []  # discovery — runs first

    def __init__(
        self,
        *,
        max_depth: int = 3,
        follow_redirects: bool = True,
        include_subdomains: bool = True,
    ) -> None:
        super().__init__()
        self.max_depth = max_depth
        self.follow_redirects = follow_redirects
        self.include_subdomains = include_subdomains
        self._crawler = Crawler(max_depth=max_depth, follow_redirects=follow_redirects)
        self._fingerprinter = Fingerprinter()
        self._header_auditor = HeaderAuditor()
        self._cors_checker = CorsChecker()
        self._content_discovery = ContentDiscovery()
        self._js_extractor = JsExtractor()
        self._ssl_analyzer = SslAnalyzer()
        self._waf_detector = WafDetector()
        self._backup_scanner = BackupScanner()
        self._fingerprint_db = FingerprintDb()
        self._method_discovery = MethodDiscovery()
        self._info_leakage = InfoLeakageScanner()
        self._dns_enum = DnsEnumerator()

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client into sub-components."""
        client = ctx.http_client
        if client:
            self._crawler.set_client(client)
            self._fingerprinter.set_client(client)
            self._header_auditor.set_client(client)
            self._cors_checker.set_client(client)
            self._content_discovery.set_client(client)
            self._js_extractor.set_client(client)
            self._waf_detector.set_client(client)
            self._backup_scanner.set_client(client)
            self._method_discovery.set_client(client)
            self._info_leakage.set_client(client)
            self._dns_enum.set_client(client)

        # Inject auth tokens into the crawler for authenticated crawling
        if ctx.auth_tokens:
            auth_headers: dict[str, str] = {}
            for key, value in ctx.auth_tokens.items():
                if key.lower() in ("authorization", "x-api-key", "cookie"):
                    auth_headers[key] = value
                elif key.lower() == "bearer":
                    auth_headers["Authorization"] = f"Bearer {value}"
            if auth_headers:
                self._crawler.inject_auth(headers=auth_headers)

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        for target in ctx.targets:
            logger.info("Crawling %s (depth=%d)", target.url, self.max_depth)
            discovered = await self._crawler.crawl(target.url)

            for url in discovered:
                ctx.add_target(Target(url=url, metadata={"discovered_by": self.name}))

            # Propagate captured cookies to context and target metadata
            cookies = self._crawler.captured_cookies
            if cookies:
                all_cookies: List[str] = []
                for url_cookies in cookies.values():
                    all_cookies.extend(url_cookies)
                target.metadata.setdefault("set_cookie_headers", []).extend(all_cookies)
                ctx.metadata.setdefault("cookies", []).extend(all_cookies)

            # Fingerprint each discovered endpoint
            techs = await self._fingerprinter.identify(target.url)
            if techs:
                findings.append(Finding(
                    title=f"Technology detected on {target.host}",
                    description=f"Technologies found: {', '.join(techs)}",
                    severity=Severity.INFO,
                    target=target,
                    tags=["recon", "fingerprint"],
                ))

            # Security header audit
            header_findings = await self._header_auditor.audit(target)
            findings.extend(header_findings)

            # CORS misconfiguration check
            cors_findings = await self._cors_checker.check(target)
            findings.extend(cors_findings)

            # Content discovery (hidden paths)
            disc_findings = await self._content_discovery.discover(target)
            findings.extend(disc_findings)

            # JavaScript secret extraction
            js_findings = await self._js_extractor.extract(target)
            findings.extend(js_findings)

            # SSL/TLS analysis
            ssl_findings = await self._ssl_analyzer.analyze(target)
            findings.extend(ssl_findings)

            # WAF detection
            waf_findings = await self._waf_detector.detect(target)
            findings.extend(waf_findings)

            # Backup / sensitive file scanning
            backup_findings = await self._backup_scanner.scan(target)
            findings.extend(backup_findings)

            # HTTP method discovery & verb tampering
            method_findings = await self._method_discovery.discover(target)
            findings.extend(method_findings)

            # Information leakage scanning
            leak_findings = await self._info_leakage.scan(target)
            findings.extend(leak_findings)

            # DNS subdomain enumeration
            dns_findings = await self._dns_enum.enumerate(target)
            findings.extend(dns_findings)

            # FingerprintDb-based technology detection
            db_detections = self._fingerprint_db.detect(
                headers=dict(target.headers) if target.headers else None,
                body=target.metadata.get("response_body", ""),
                cookies={k: v for k, v in (target.metadata.get("cookies_dict") or {}).items()},
            )
            if db_detections:
                tech_names = [d["name"] for d in db_detections]
                findings.append(Finding(
                    title=f"Technologies detected (fingerprint DB) on {target.host}",
                    description=f"Detected: {', '.join(tech_names)}",
                    severity=Severity.INFO,
                    target=target,
                    tags=["recon", "fingerprint-db"],
                ))

            logger.info(
                "Discovered %d endpoints, %d technologies, %d header, %d CORS, %d content, %d JS, %d SSL findings on %s",
                len(discovered), len(techs), len(header_findings), len(cors_findings),
                len(disc_findings), len(js_findings), len(ssl_findings),
                target.url,
            )

        for f in findings:
            self.add_finding(f)
        return findings
