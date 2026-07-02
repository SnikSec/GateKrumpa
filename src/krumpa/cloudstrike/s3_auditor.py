"""
CloudStrike — S3 bucket security auditor (Epic 4).

Safe, read-only checks per bucket:
  - Public ACL / bucket policy
  - Public access block settings
  - CORS wildcard origins
  - Server-side encryption
  - Versioning status
  - Cross-account replication rules
  - Predictable naming patterns tied to discovered domains
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.s3_auditor")

_SENSITIVE_NAME_PATTERNS = [
    re.compile(r"backup|bak|dump|export|archive", re.IGNORECASE),
    re.compile(r"secret|credential|password|private|key", re.IGNORECASE),
    re.compile(r"log|audit|trail", re.IGNORECASE),
    re.compile(r"ml|model|training|dataset|embedding", re.IGNORECASE),
]


class S3Auditor:
    """Audit S3 buckets for public access, CORS, encryption, and data exposure risks."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory = ctx.metadata.get("aws_inventory", {})
        buckets = inventory.get("s3_buckets", [])
        if not buckets:
            return findings

        client = self._session.client("s3")

        for bucket in buckets:
            findings.extend(self._check_public_access_block(client, bucket, target))
            findings.extend(self._check_bucket_acl(client, bucket, target))
            findings.extend(self._check_bucket_policy(client, bucket, target))
            findings.extend(self._check_cors(client, bucket, target))
            findings.extend(self._check_encryption(client, bucket, target))
            findings.extend(self._check_versioning(client, bucket, target))
            findings.extend(self._check_replication(client, bucket, target))
            findings.extend(self._check_sensitive_naming(bucket, target))

        return findings

    # ------------------------------------------------------------------

    def _check_public_access_block(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            resp = client.get_public_access_block(Bucket=bucket)
            config = resp.get("PublicAccessBlockConfiguration", {})
            missing = [k for k, v in config.items() if not v]
            if missing:
                return [Finding(
                    title=f"S3 public access block not fully enabled: {bucket}",
                    description=(
                        f"Bucket {bucket!r} has incomplete public access block settings. "
                        "This allows public ACLs or policies to expose objects."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Disabled settings: {', '.join(missing)}",
                    remediation=(
                        "Enable all four public access block settings: "
                        "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
                    ),
                    cwe=284,
                    tags=["cloud", "aws", "s3", "public-access"],
                )]
        except client.exceptions.NoSuchPublicAccessBlockConfiguration:
            return [Finding(
                title=f"S3 public access block absent: {bucket}",
                description=f"Bucket {bucket!r} has no public access block configuration.",
                severity=Severity.HIGH,
                target=target,
                evidence=f"s3://{bucket} — no PublicAccessBlockConfiguration",
                remediation="Apply the S3 Block Public Access settings at the bucket level.",
                cwe=284,
                tags=["cloud", "aws", "s3", "public-access"],
            )]
        except Exception as exc:
            logger.debug("PublicAccessBlock check failed for %s: %s", bucket, exc)
        return []

    def _check_bucket_acl(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            resp = client.get_bucket_acl(Bucket=bucket)
            for grant in resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    return [Finding(
                        title=f"S3 bucket publicly accessible via ACL: {bucket}",
                        description=(
                            f"Bucket {bucket!r} grants access to AllUsers or "
                            "AuthenticatedUsers via ACL."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=f"ACL grantee URI: {uri}\nPermission: {grant.get('Permission')}",
                        remediation="Remove public ACL grants. Use bucket policies with explicit principals instead.",
                        cwe=284,
                        tags=["cloud", "aws", "s3", "public-acl", "data-exposure"],
                    )]
        except Exception as exc:
            logger.debug("ACL check failed for %s: %s", bucket, exc)
        return []

    def _check_bucket_policy(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            policy_str = client.get_bucket_policy(Bucket=bucket).get("Policy", "{}")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", {})
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    return [Finding(
                        title=f"S3 bucket policy allows public access: {bucket}",
                        description=(
                            f"Bucket {bucket!r} has a bucket policy with Principal=* "
                            "and Effect=Allow, making it publicly accessible."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=f"Statement: {json.dumps(stmt, indent=2)[:500]}",
                        remediation="Remove or restrict the public principal in the bucket policy.",
                        cwe=284,
                        tags=["cloud", "aws", "s3", "public-policy", "data-exposure"],
                    )]
        except client.exceptions.NoSuchBucketPolicy:
            pass
        except Exception as exc:
            logger.debug("Policy check failed for %s: %s", bucket, exc)
        return []

    def _check_cors(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            cors_rules = client.get_bucket_cors(Bucket=bucket).get("CORSRules", [])
            for rule in cors_rules:
                origins = rule.get("AllowedOrigins", [])
                if "*" in origins:
                    return [Finding(
                        title=f"S3 CORS wildcard origin: {bucket}",
                        description=(
                            f"Bucket {bucket!r} allows CORS requests from any origin (*). "
                            "This can enable cross-site data exfiltration."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"AllowedOrigins: {origins}\nAllowedMethods: {rule.get('AllowedMethods', [])}",
                        remediation="Restrict AllowedOrigins to specific trusted domains.",
                        cwe=346,
                        tags=["cloud", "aws", "s3", "cors"],
                    )]
        except client.exceptions.NoSuchCORSConfiguration:
            pass
        except Exception as exc:
            logger.debug("CORS check failed for %s: %s", bucket, exc)
        return []

    def _check_encryption(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            client.get_bucket_encryption(Bucket=bucket)
        except client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            return [Finding(
                title=f"S3 bucket not encrypted at rest: {bucket}",
                description=f"Bucket {bucket!r} has no default server-side encryption.",
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"s3://{bucket} — no SSE configuration",
                remediation="Enable AES-256 or SSE-KMS default encryption on the bucket.",
                cwe=311,
                tags=["cloud", "aws", "s3", "encryption"],
            )]
        except Exception as exc:
            logger.debug("Encryption check failed for %s: %s", bucket, exc)
        return []

    def _check_versioning(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            resp = client.get_bucket_versioning(Bucket=bucket)
            status = resp.get("Status", "")
            if status != "Enabled":
                return [Finding(
                    title=f"S3 bucket versioning disabled: {bucket}",
                    description=(
                        f"Bucket {bucket!r} does not have versioning enabled. "
                        "Without versioning, accidental or malicious deletions are not recoverable."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=f"Versioning status: {status or 'Not configured'}",
                    remediation="Enable versioning and consider MFA Delete for sensitive buckets.",
                    cwe=284,
                    tags=["cloud", "aws", "s3", "versioning"],
                )]
        except Exception as exc:
            logger.debug("Versioning check failed for %s: %s", bucket, exc)
        return []

    def _check_replication(self, client: Any, bucket: str, target: Target) -> List[Finding]:
        try:
            rules = client.get_bucket_replication(Bucket=bucket).get("ReplicationConfiguration", {}).get("Rules", [])
            for rule in rules:
                dest_bucket = rule.get("Destination", {}).get("Bucket", "")
                dest_account = rule.get("Destination", {}).get("Account", "")
                if dest_account and dest_account != self._get_account_id():
                    return [Finding(
                        title=f"S3 cross-account replication rule: {bucket}",
                        description=(
                            f"Bucket {bucket!r} replicates to another AWS account "
                            f"({dest_account}). This may be an intentional backup or "
                            "an unauthorized data exfiltration channel."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Destination: {dest_bucket}\nDestination account: {dest_account}",
                        remediation="Verify the destination account is authorized. Remove unauthorized replication rules.",
                        cwe=285,
                        tags=["cloud", "aws", "s3", "replication", "data-exfiltration"],
                    )]
        except client.exceptions.ReplicationConfigurationNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Replication check failed for %s: %s", bucket, exc)
        return []

    def _check_sensitive_naming(self, bucket: str, target: Target) -> List[Finding]:
        for pattern in _SENSITIVE_NAME_PATTERNS:
            if pattern.search(bucket):
                return [Finding(
                    title=f"S3 bucket with sensitive name pattern: {bucket}",
                    description=(
                        f"Bucket {bucket!r} has a name suggesting it may contain "
                        "sensitive data (backups, credentials, ML training data, etc.)."
                    ),
                    severity=Severity.INFO,
                    target=target,
                    evidence=f"Bucket name: {bucket}",
                    tags=["cloud", "aws", "s3", "sensitive-data", "naming"],
                )]
        return []

    def _get_account_id(self) -> str:
        try:
            return self._session.client("sts").get_caller_identity()["Account"]
        except Exception:
            return ""
