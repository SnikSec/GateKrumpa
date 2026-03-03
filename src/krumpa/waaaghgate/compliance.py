"""
WaaaghGate — Compliance mapping engine.

Maps CWE IDs to OWASP Top 10, OWASP API Top 10, PCI-DSS, NIST, and
SANS/CWE Top 25 categories.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


# CWE → OWASP Top 10 (2021) mapping
_CWE_TO_OWASP_WEB: Dict[int, str] = {
    # A01 Broken Access Control
    22: "A01:2021-Broken Access Control",
    269: "A01:2021-Broken Access Control",
    284: "A01:2021-Broken Access Control",
    285: "A01:2021-Broken Access Control",
    306: "A01:2021-Broken Access Control",
    352: "A01:2021-Broken Access Control",
    425: "A01:2021-Broken Access Control",
    601: "A01:2021-Broken Access Control",
    639: "A01:2021-Broken Access Control",
    862: "A01:2021-Broken Access Control",
    863: "A01:2021-Broken Access Control",
    # A02 Cryptographic Failures
    295: "A02:2021-Cryptographic Failures",
    319: "A02:2021-Cryptographic Failures",
    326: "A02:2021-Cryptographic Failures",
    327: "A02:2021-Cryptographic Failures",
    523: "A02:2021-Cryptographic Failures",
    # A03 Injection
    77: "A03:2021-Injection",
    78: "A03:2021-Injection",
    79: "A03:2021-Injection",
    89: "A03:2021-Injection",
    94: "A03:2021-Injection",
    113: "A03:2021-Injection",
    611: "A03:2021-Injection",
    644: "A03:2021-Injection",
    917: "A03:2021-Injection",
    943: "A03:2021-Injection",
    # A04 Insecure Design
    200: "A04:2021-Insecure Design",
    209: "A04:2021-Insecure Design",
    256: "A04:2021-Insecure Design",
    501: "A04:2021-Insecure Design",
    # A05 Security Misconfiguration
    16: "A05:2021-Security Misconfiguration",
    489: "A05:2021-Security Misconfiguration",
    530: "A05:2021-Security Misconfiguration",
    538: "A05:2021-Security Misconfiguration",
    # A06 Vulnerable and Outdated Components
    1035: "A06:2021-Vulnerable and Outdated Components",
    # A07 Authentication Failures
    287: "A07:2021-Identification and Authentication Failures",
    290: "A07:2021-Identification and Authentication Failures",
    307: "A07:2021-Identification and Authentication Failures",
    347: "A07:2021-Identification and Authentication Failures",
    384: "A07:2021-Identification and Authentication Failures",
    521: "A07:2021-Identification and Authentication Failures",
    613: "A07:2021-Identification and Authentication Failures",
    798: "A07:2021-Identification and Authentication Failures",
    799: "A07:2021-Identification and Authentication Failures",
    # A08 Software and Data Integrity
    345: "A08:2021-Software and Data Integrity Failures",
    502: "A08:2021-Software and Data Integrity Failures",
    829: "A08:2021-Software and Data Integrity Failures",
    915: "A08:2021-Software and Data Integrity Failures",
    # A09 Security Logging & Monitoring
    # A10 SSRF
    918: "A10:2021-Server-Side Request Forgery",
}

# CWE → OWASP API Top 10 (2023)
_CWE_TO_OWASP_API: Dict[int, str] = {
    285: "API1:2023-Broken Object Level Authorization",
    639: "API1:2023-Broken Object Level Authorization",
    862: "API1:2023-Broken Object Level Authorization",
    287: "API2:2023-Broken Authentication",
    307: "API2:2023-Broken Authentication",
    384: "API2:2023-Broken Authentication",
    521: "API2:2023-Broken Authentication",
    613: "API2:2023-Broken Authentication",
    200: "API3:2023-Broken Object Property Level Authorization",
    915: "API3:2023-Broken Object Property Level Authorization",
    770: "API4:2023-Unrestricted Resource Consumption",
    799: "API4:2023-Unrestricted Resource Consumption",
    269: "API5:2023-Broken Function Level Authorization",
    306: "API5:2023-Broken Function Level Authorization",
    863: "API5:2023-Broken Function Level Authorization",
    918: "API7:2023-Server Side Request Forgery",
    16: "API8:2023-Security Misconfiguration",
    489: "API8:2023-Security Misconfiguration",
    538: "API8:2023-Security Misconfiguration",
}

# CWE → PCI-DSS v4.0 requirements
_CWE_TO_PCI: Dict[int, str] = {
    79: "PCI-DSS 6.2.4 - Software engineering techniques to prevent injection",
    89: "PCI-DSS 6.2.4 - Software engineering techniques to prevent injection",
    78: "PCI-DSS 6.2.4 - Software engineering techniques to prevent injection",
    943: "PCI-DSS 6.2.4 - Software engineering techniques to prevent injection",
    306: "PCI-DSS 7.2.1 - Access control system",
    269: "PCI-DSS 7.2.1 - Access control system",
    639: "PCI-DSS 7.2.1 - Access control system",
    287: "PCI-DSS 8.2.1 - Strong authentication",
    307: "PCI-DSS 8.2.1 - Strong authentication",
    521: "PCI-DSS 8.2.1 - Strong authentication",
    319: "PCI-DSS 4.2.1 - Strong cryptography for transmission",
    326: "PCI-DSS 4.2.1 - Strong cryptography for transmission",
    327: "PCI-DSS 4.2.1 - Strong cryptography for transmission",
    200: "PCI-DSS 3.4.1 - PAN is rendered unreadable",
}


class ComplianceMapper:
    """Map findings to compliance frameworks."""

    def map_finding(self, cwe: Optional[int]) -> Dict[str, str]:
        """Return all compliance mappings for a CWE ID."""
        if cwe is None:
            return {}

        result: Dict[str, str] = {}

        owasp_web = _CWE_TO_OWASP_WEB.get(cwe)
        if owasp_web:
            result["owasp_web_2021"] = owasp_web

        owasp_api = _CWE_TO_OWASP_API.get(cwe)
        if owasp_api:
            result["owasp_api_2023"] = owasp_api

        pci = _CWE_TO_PCI.get(cwe)
        if pci:
            result["pci_dss_v4"] = pci

        return result

    def map_findings(self, findings: list) -> List[Dict[str, Any]]:
        """Annotate each finding with compliance mappings."""
        annotated = []
        for f in findings:
            cwe = getattr(f, "cwe", None)
            mapping = self.map_finding(cwe)
            annotated.append({
                "title": f.title,
                "cwe": cwe,
                "compliance": mapping,
            })
        return annotated

    def summary(self, findings: list) -> Dict[str, Set[str]]:
        """Group findings by compliance category."""
        by_framework: Dict[str, Set[str]] = {}
        for f in findings:
            cwe = getattr(f, "cwe", None)
            mapping = self.map_finding(cwe)
            for framework, category in mapping.items():
                by_framework.setdefault(framework, set()).add(category)
        return by_framework

    @staticmethod
    def all_owasp_web_categories() -> List[str]:
        return sorted(set(_CWE_TO_OWASP_WEB.values()))

    @staticmethod
    def all_owasp_api_categories() -> List[str]:
        return sorted(set(_CWE_TO_OWASP_API.values()))
