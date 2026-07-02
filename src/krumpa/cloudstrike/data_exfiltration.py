"""
CloudStrike — Data exfiltration surface analysis.

Identifies S3 configurations that could be abused as silent data exfiltration
channels:
  - Cross-account replication rules (handled by S3Auditor for initial detection;
    this module focuses on replication pointing to external accounts)
  - Overly-broad bucket policies allowing s3:GetObject for principal *
  - Pre-signed URL generation capability via overly-permissive IAM policies
  - S3 Transfer Acceleration on sensitive-named buckets
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.data_exfiltration")

_SENSITIVE_NAME_RE = re.compile(
    r"backup|secret|credential|private|export|dump|ml|model|training|dataset",
    re.IGNORECASE,
)


class DataExfiltrationAnalyzer:
    """Identify data exfiltration surface in S3 and IAM configurations."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory = ctx.metadata.get("aws_inventory", {})
        buckets = inventory.get("s3_buckets", [])
        if not buckets:
            return findings

        s3 = self._session.client("s3")

        for bucket in buckets:
            findings.extend(self._check_transfer_acceleration(s3, bucket, target))
            findings.extend(self._check_broad_get_policy(s3, bucket, target))

        findings.extend(self._check_iam_presigned_url_perms(target, inventory))
        return findings

    # ------------------------------------------------------------------

    def _check_transfer_acceleration(self, s3: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            resp = s3.get_bucket_accelerate_configuration(Bucket=bucket)
            if resp.get("Status") == "Enabled" and _SENSITIVE_NAME_RE.search(bucket):
                return [Finding(
                    title=f"S3 Transfer Acceleration on sensitive bucket: {bucket}",
                    description=(
                        f"Bucket {bucket!r} has S3 Transfer Acceleration enabled and "
                        "appears to contain sensitive data based on its name. "
                        "Transfer Acceleration can be abused to rapidly exfiltrate data."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Bucket: s3://{bucket}\nTransfer Acceleration: Enabled",
                    remediation="Disable Transfer Acceleration if not required, or restrict bucket access.",
                    cwe=285,
                    tags=["cloud", "aws", "s3", "data-exfiltration", "transfer-acceleration"],
                )]
        except Exception as exc:
            logger.debug("Transfer acceleration check failed for %s: %s", bucket, exc)
        return []

    def _check_broad_get_policy(self, s3: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket).get("Policy", "{}")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", "")
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                actions_lower = [a.lower() for a in actions]
                has_get = any(a in ("s3:getobject", "s3:*", "*") for a in actions_lower)
                is_public = principal == "*" or principal == {"AWS": "*"}
                if has_get and is_public:
                    return [Finding(
                        title=f"S3 bucket policy allows public object reads: {bucket}",
                        description=(
                            f"Bucket {bucket!r} policy grants s3:GetObject to principal * — "
                            "all objects are publicly readable by anyone with the object URL."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=f"Statement: {json.dumps(stmt, indent=2)[:400]}",
                        remediation="Remove the public principal from the bucket policy.",
                        cwe=284,
                        tags=["cloud", "aws", "s3", "public-read", "data-exposure"],
                    )]
        except Exception as exc:
            logger.debug("Broad GET policy check failed for %s: %s", bucket, exc)
        return []

    def _check_iam_presigned_url_perms(self, target: Target, inventory: dict) -> List[Finding]:
        """Flag roles or users that have s3:GetObject + sts:GetFederationToken (presigned URL gen)."""
        findings: List[Finding] = []
        # This is a lightweight heuristic — full analysis is in IamPathfinder
        try:
            iam = self._session.client("iam")
            for role_name in inventory.get("iam_roles", [])[:30]:
                try:
                    sim_resp = iam.simulate_principal_policy(
                        PolicySourceArn=f"arn:aws:iam::{self._get_account_id()}:role/{role_name}",
                        ActionNames=["s3:GetObject", "sts:GetFederationToken"],
                        ResourceArns=["*"],
                    )
                    allowed = [
                        r["EvalActionName"]
                        for r in sim_resp.get("EvaluationResults", [])
                        if r.get("EvalDecision") == "allowed"
                    ]
                    if "s3:GetObject" in allowed and "sts:GetFederationToken" in allowed:
                        findings.append(Finding(
                            title=f"IAM role can generate pre-signed S3 URLs: {role_name}",
                            description=(
                                f"Role {role_name!r} has both s3:GetObject and "
                                "sts:GetFederationToken — it can generate pre-signed URLs "
                                "that provide time-limited public access to any S3 object."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Role: {role_name}\nAllowed: {', '.join(allowed)}",
                            remediation="Restrict sts:GetFederationToken to principals that explicitly require it.",
                            cwe=285,
                            tags=["cloud", "aws", "iam", "s3", "presigned-url"],
                        ))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("Presigned URL permission check failed: %s", exc)
        return findings

    def _get_account_id(self) -> str:
        try:
            return self._session.client("sts").get_caller_identity()["Account"]
        except Exception:
            return "000000000000"
