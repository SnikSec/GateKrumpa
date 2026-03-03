"""
SneakyGits — Recon module.

Responsibilities:
    - Endpoint discovery (sitemap, robots.txt, link crawling)
    - Technology fingerprinting (headers, body patterns, cookies)
    - Subdomain enumeration
"""

from krumpa.sneakygits.crawler import Crawler
from krumpa.sneakygits.fingerprint import Fingerprinter
from krumpa.sneakygits.content_discovery import ContentDiscovery
from krumpa.sneakygits.js_extractor import JsExtractor
from krumpa.sneakygits.ssl_analyzer import SslAnalyzer
from krumpa.sneakygits.waf_detector import WafDetector
from krumpa.sneakygits.backup_scanner import BackupScanner
from krumpa.sneakygits.fingerprint_db import FingerprintDb, TechSignature
from krumpa.sneakygits.module import SneakyGitsModule

__all__ = [
    "SneakyGitsModule",
    "Crawler",
    "Fingerprinter",
    "ContentDiscovery",
    "JsExtractor",
    "SslAnalyzer",
    "WafDetector",
    "BackupScanner",
    "FingerprintDb",
    "TechSignature",
]
