"""
SneakyGits — Security Header Auditor.

Checks HTTP responses for the presence and correctness of standard
security headers recommended by OWASP, Mozilla Observatory, and
industry best practice.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.headers")


# ------------------------------------------------------------------
# Header definitions — what we check and how
# ------------------------------------------------------------------

@dataclass(frozen=True)
class _HeaderCheck(HttpClientMixin):
    """Describes a single security-header expectation."""
    name: str                       # HTTP header name (case-insensitive)
    required: bool                  # Is absence alone a finding?
    severity_missing: Severity      # Severity when entirely absent
    description_missing: str        # Finding description when absent
    remediation: str                # How to fix
    cwe: Optional[int] = None      # CWE ID
    validators: tuple = ()          # Callables returning (ok, detail_msg)


def _validate_hsts_max_age(value: str) -> tuple[bool, str]:
    """HSTS max-age should be at least 31536000 (1 year)."""
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return False, "HSTS header present but missing max-age directive"
    age = int(match.group(1))
    if age < 31536000:
        return False, f"HSTS max-age is {age} — should be ≥ 31536000 (1 year)"
    return True, ""


def _validate_hsts_subdomains(value: str) -> tuple[bool, str]:
    if "includesubdomains" not in value.lower():
        return False, "HSTS missing includeSubDomains directive"
    return True, ""


def _validate_xcto(value: str) -> tuple[bool, str]:
    if value.strip().lower() != "nosniff":
        return False, f"X-Content-Type-Options should be 'nosniff', got '{value.strip()}'"
    return True, ""


def _validate_xfo(value: str) -> tuple[bool, str]:
    val = value.strip().lower()
    if val not in ("deny", "sameorigin"):
        return False, f"X-Frame-Options should be DENY or SAMEORIGIN, got '{value.strip()}'"
    return True, ""


def _validate_referrer_policy(value: str) -> tuple[bool, str]:
    safe_policies = {
        "no-referrer", "no-referrer-when-downgrade",
        "same-origin", "origin", "strict-origin",
        "origin-when-cross-origin", "strict-origin-when-cross-origin",
    }
    val = value.strip().lower()
    if val not in safe_policies:
        return False, f"Referrer-Policy '{val}' may leak referrer data"
    return True, ""


def _validate_csp_present(value: str) -> tuple[bool, str]:
    """Basic CSP validation — just check it's not obviously broken."""
    if "unsafe-inline" in value.lower() and "nonce-" not in value.lower() and "strict-dynamic" not in value.lower():
        return False, "CSP contains 'unsafe-inline' without nonce or strict-dynamic — XSS risk"
    if "unsafe-eval" in value.lower():
        return False, "CSP contains 'unsafe-eval' — code injection risk"
    return True, ""


# Master checklist
SECURITY_HEADERS: List[_HeaderCheck] = [
    _HeaderCheck(
        name="Strict-Transport-Security",
        required=True,
        severity_missing=Severity.MEDIUM,
        description_missing=(
            "Strict-Transport-Security (HSTS) header is missing. "
            "Without HSTS, browsers may connect over plain HTTP, exposing "
            "traffic to interception."
        ),
        remediation="Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        cwe=523,
        validators=(_validate_hsts_max_age, _validate_hsts_subdomains),
    ),
    _HeaderCheck(
        name="Content-Security-Policy",
        required=True,
        severity_missing=Severity.MEDIUM,
        description_missing=(
            "Content-Security-Policy (CSP) header is missing. "
            "CSP mitigates XSS by restricting resource loading."
        ),
        remediation="Define a CSP that restricts script-src, object-src, and base-uri.",
        cwe=693,
        validators=(_validate_csp_present,),
    ),
    _HeaderCheck(
        name="X-Content-Type-Options",
        required=True,
        severity_missing=Severity.LOW,
        description_missing=(
            "X-Content-Type-Options header is missing. "
            "Browsers may MIME-sniff responses, leading to XSS."
        ),
        remediation="Set `X-Content-Type-Options: nosniff`.",
        cwe=16,
        validators=(_validate_xcto,),
    ),
    _HeaderCheck(
        name="X-Frame-Options",
        required=True,
        severity_missing=Severity.MEDIUM,
        description_missing=(
            "X-Frame-Options header is missing. "
            "The page may be framed, enabling clickjacking attacks."
        ),
        remediation="Set `X-Frame-Options: DENY` or `SAMEORIGIN`.",
        cwe=1021,
        validators=(_validate_xfo,),
    ),
    _HeaderCheck(
        name="Referrer-Policy",
        required=True,
        severity_missing=Severity.LOW,
        description_missing=(
            "Referrer-Policy header is missing. "
            "Full URLs (including tokens in query strings) may be leaked via the Referer header."
        ),
        remediation="Set `Referrer-Policy: strict-origin-when-cross-origin`.",
        cwe=200,
        validators=(_validate_referrer_policy,),
    ),
    _HeaderCheck(
        name="Permissions-Policy",
        required=True,
        severity_missing=Severity.LOW,
        description_missing=(
            "Permissions-Policy header is missing. "
            "Browser features (camera, microphone, geolocation) are not restricted."
        ),
        remediation="Set a Permissions-Policy limiting unnecessary browser features.",
        cwe=16,
    ),
    _HeaderCheck(
        name="Cross-Origin-Opener-Policy",
        required=False,
        severity_missing=Severity.INFO,
        description_missing=(
            "Cross-Origin-Opener-Policy (COOP) header is missing. "
            "COOP isolates the browsing context, preventing side-channel attacks."
        ),
        remediation="Set `Cross-Origin-Opener-Policy: same-origin`.",
    ),
    _HeaderCheck(
        name="Cross-Origin-Resource-Policy",
        required=False,
        severity_missing=Severity.INFO,
        description_missing=(
            "Cross-Origin-Resource-Policy (CORP) header is missing. "
            "CORP prevents cross-origin reads of the resource."
        ),
        remediation="Set `Cross-Origin-Resource-Policy: same-origin`.",
    ),
    _HeaderCheck(
        name="Cross-Origin-Embedder-Policy",
        required=False,
        severity_missing=Severity.INFO,
        description_missing=(
            "Cross-Origin-Embedder-Policy (COEP) header is missing."
        ),
        remediation="Set `Cross-Origin-Embedder-Policy: require-corp`.",
    ),
]


# ------------------------------------------------------------------
# Auditor
# ------------------------------------------------------------------

class HeaderAuditor(HttpClientMixin):
    """
    Fetch a URL and audit its security headers.

    Usage::

        auditor = HeaderAuditor()
        findings = await auditor.audit(target)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        checks: Optional[List[_HeaderCheck]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._checks = checks if checks is not None else list(SECURITY_HEADERS)

    async def audit(self, target: Target) -> List[Finding]:
        """Audit the given target's response headers."""
        client = self._client or HttpClient()
        try:
            resp = await client.get(target.url)
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Header audit failed for %s: %s", target.url, exc)
            return []
        finally:
            if self._owns_client and not self._client:
                await client.close()

        return self._evaluate(target, resp.headers)

    def _evaluate(
        self,
        target: Target,
        headers: httpx.Headers,
    ) -> List[Finding]:
        """Check response headers against all configured checks."""
        findings: List[Finding] = []

        for check in self._checks:
            value = headers.get(check.name)

            if value is None:
                if check.required:
                    findings.append(Finding(
                        title=f"Missing security header: {check.name}",
                        description=check.description_missing,
                        severity=check.severity_missing,
                        target=target,
                        remediation=check.remediation,
                        cwe=check.cwe,
                        tags=["recon", "headers", "config"],
                    ))
                elif check.severity_missing != Severity.INFO:
                    findings.append(Finding(
                        title=f"Missing security header: {check.name}",
                        description=check.description_missing,
                        severity=check.severity_missing,
                        target=target,
                        remediation=check.remediation,
                        cwe=check.cwe,
                        tags=["recon", "headers", "config"],
                    ))
                continue

            # Header present — run validators
            for validator in check.validators:
                ok, detail = validator(value)
                if not ok:
                    findings.append(Finding(
                        title=f"Weak security header: {check.name}",
                        description=detail,
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"{check.name}: {value}",
                        remediation=check.remediation,
                        cwe=check.cwe,
                        tags=["recon", "headers", "config"],
                    ))

        # Bonus: check for information-leaking headers
        for leak_header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            val = headers.get(leak_header)
            if val and ("/" in val or re.search(r"\d", val)):
                findings.append(Finding(
                    title=f"Information disclosure via {leak_header} header",
                    description=(
                        f"The {leak_header} header reveals version information: '{val}'. "
                        f"This aids attackers in identifying known vulnerabilities for the software version."
                    ),
                    severity=Severity.INFO,
                    target=target,
                    evidence=f"{leak_header}: {val}",
                    remediation=f"Remove or suppress the {leak_header} header.",
                    cwe=200,
                    tags=["recon", "headers", "info-leak"],
                ))

        return findings
