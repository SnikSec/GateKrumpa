"""
CloudStrike — IMDS exposure and service-account credential analysis.

Checks whether EC2 instances allow IMDSv1 (token-free) requests and
correlates with any SSRF findings in the scan context to estimate
whether credential theft is feasible via SSRF.
"""

from __future__ import annotations

import logging
from typing import Any, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.metadata_service")


class MetadataServiceAnalyzer:
    """Detect IMDSv1 exposure and SSRF-to-IMDS attack viability."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory = ctx.metadata.get("aws_inventory", {})
        instances = inventory.get("ec2_instances", [])

        # Find instances where IMDSv2 is NOT enforced
        imdsv1_instances = [i for i in instances if not i.get("imdsv2_required", False)]
        if not imdsv1_instances:
            return findings

        # Check if any SSRF findings exist in the scan context
        ssrf_findings = [
            f for f in ctx.findings
            if any(t in f.tags for t in ("ssrf", "cloud-metadata"))
        ]

        if ssrf_findings:
            # SSRF + IMDSv1 = active CRITICAL attack chain
            findings.append(Finding(
                title="SSRF-to-IMDS credential theft chain identified",
                description=(
                    "One or more SSRF vulnerabilities were found on web-tier targets "
                    "AND the EC2 environment allows IMDSv1 (unauthenticated IMDS requests). "
                    "An attacker can use the SSRF to fetch "
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                    "and steal the instance role's temporary AWS credentials."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=(
                    f"SSRF findings: {len(ssrf_findings)}\n"
                    f"IMDSv1-enabled instances: {len(imdsv1_instances)}\n"
                    "Sample instances: " + ", ".join(
                        i.get("id", "?") for i in imdsv1_instances[:5]
                    )
                ),
                remediation=(
                    "1. Enforce IMDSv2 on all EC2 instances (HttpTokens=required). "
                    "2. Remediate the SSRF vulnerabilities identified in this scan. "
                    "3. Restrict instance role permissions to least privilege."
                ),
                cwe=918,
                tags=["cloud", "aws", "imds", "ssrf", "credential-theft", "attack-chain"],
            ))
        else:
            # IMDSv1 present but no SSRF confirmed yet — still HIGH
            findings.append(Finding(
                title=f"IMDSv1 enabled on {len(imdsv1_instances)} EC2 instance(s)",
                description=(
                    "EC2 instances allow unauthenticated IMDS requests (IMDSv1). "
                    "If any application running on these instances is vulnerable to "
                    "SSRF, an attacker can retrieve temporary IAM credentials."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="Instances: " + ", ".join(
                    i.get("id", "?") for i in imdsv1_instances[:10]
                ),
                remediation=(
                    "Enforce IMDSv2 by setting HttpTokens=required via the "
                    "EC2 ModifyInstanceMetadataOptions API or instance launch template."
                ),
                cwe=693,
                tags=["cloud", "aws", "imds", "imdsv1"],
            ))

        return findings
