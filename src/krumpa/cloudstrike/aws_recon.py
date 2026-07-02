"""
CloudStrike — AWS asset enumeration.

Read-only enumeration of S3, EC2, IAM, Lambda, ECR, EKS, SageMaker, and
Bedrock surfaces.  Emits INFO findings that serve as the asset inventory
consumed by downstream analyzers (IamPathfinder, S3Auditor, etc.).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.aws_recon")


class AwsRecon:
    """Enumerate AWS resources and store the inventory in ScanContext.metadata."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory: Dict[str, Any] = {}

        findings.extend(self._enumerate_s3(target, inventory))
        findings.extend(self._enumerate_iam(target, inventory))
        findings.extend(self._enumerate_ec2(target, inventory))
        findings.extend(self._enumerate_lambda(target, inventory))
        findings.extend(self._enumerate_ecr(target, inventory))
        findings.extend(self._enumerate_eks(target, inventory))
        findings.extend(self._enumerate_sagemaker(target, inventory))
        findings.extend(self._enumerate_bedrock(target, inventory))

        # Store inventory for downstream analyzers
        ctx.metadata.setdefault("aws_inventory", {}).update(inventory)
        return findings

    # ------------------------------------------------------------------

    def _enumerate_s3(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("s3")
            resp = client.list_buckets()
            buckets = [b["Name"] for b in resp.get("Buckets", [])]
            inventory["s3_buckets"] = buckets
            if buckets:
                findings.append(Finding(
                    title=f"S3 buckets enumerated ({len(buckets)})",
                    description=f"Found {len(buckets)} S3 buckets in the account.",
                    severity=Severity.INFO,
                    target=target,
                    evidence="\n".join(f"  s3://{b}" for b in buckets[:50]),
                    tags=["cloud", "aws", "s3", "recon"],
                ))
        except Exception as exc:
            logger.debug("S3 enumeration failed: %s", exc)
        return findings

    def _enumerate_iam(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("iam")
            users = [u["UserName"] for u in client.list_users().get("Users", [])]
            roles = [r["RoleName"] for r in client.list_roles().get("Roles", [])]
            inventory["iam_users"] = users
            inventory["iam_roles"] = roles
            findings.append(Finding(
                title=f"IAM inventory: {len(users)} users, {len(roles)} roles",
                description="IAM users and roles enumerated for privilege escalation path analysis.",
                severity=Severity.INFO,
                target=target,
                evidence=(
                    f"Users ({len(users)}): {', '.join(users[:20])}\n"
                    f"Roles ({len(roles)}): {', '.join(roles[:20])}"
                ),
                tags=["cloud", "aws", "iam", "recon"],
            ))
        except Exception as exc:
            logger.debug("IAM enumeration failed: %s", exc)
        return findings

    def _enumerate_ec2(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("ec2")
            resp = client.describe_instances()
            instances = []
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    instances.append({
                        "id": inst.get("InstanceId"),
                        "type": inst.get("InstanceType"),
                        "state": inst.get("State", {}).get("Name"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                        "imdsv2_required": inst.get("MetadataOptions", {}).get("HttpTokens") == "required",
                    })
            inventory["ec2_instances"] = instances
            imdsv1_count = sum(1 for i in instances if not i["imdsv2_required"])
            if imdsv1_count:
                findings.append(Finding(
                    title=f"EC2 instances with IMDSv1 enabled ({imdsv1_count})",
                    description=(
                        f"{imdsv1_count} EC2 instance(s) do not require IMDSv2 token authentication. "
                        "IMDSv1 is susceptible to SSRF-based credential theft."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence="\n".join(
                        f"  {i['id']} ({i['type']}, {i['state']}, public_ip={i['public_ip']})"
                        for i in instances if not i["imdsv2_required"]
                    )[:2000],
                    remediation="Enforce IMDSv2 by setting HttpTokens=required on all EC2 instances.",
                    cwe=693,
                    tags=["cloud", "aws", "ec2", "imds", "ssrf-risk"],
                ))
            else:
                findings.append(Finding(
                    title=f"EC2 instances enumerated ({len(instances)})",
                    description=f"{len(instances)} EC2 instance(s) found; all require IMDSv2.",
                    severity=Severity.INFO,
                    target=target,
                    tags=["cloud", "aws", "ec2", "recon"],
                ))
        except Exception as exc:
            logger.debug("EC2 enumeration failed: %s", exc)
        return findings

    def _enumerate_lambda(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("lambda")
            paginator = client.get_paginator("list_functions")
            functions = []
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    env_vars = list((fn.get("Environment") or {}).get("Variables", {}).keys())
                    functions.append({
                        "name": fn["FunctionName"],
                        "runtime": fn.get("Runtime"),
                        "role": fn.get("Role"),
                        "env_var_keys": env_vars,
                    })
            inventory["lambda_functions"] = functions
            # Flag functions with sensitive-looking env var names
            sensitive_keys = {"DATABASE_URL", "DB_PASSWORD", "SECRET_KEY", "API_KEY",
                              "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "TOKEN", "PASSWORD"}
            flagged = [
                f for f in functions
                if any(k.upper() in sensitive_keys for k in f["env_var_keys"])
            ]
            if flagged:
                findings.append(Finding(
                    title=f"Lambda functions with sensitive env vars ({len(flagged)})",
                    description=(
                        "Lambda functions have environment variable keys that suggest "
                        "hardcoded secrets. Env vars are visible to anyone with "
                        "lambda:GetFunctionConfiguration permissions."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence="\n".join(
                        f"  {f['name']}: {', '.join(f['env_var_keys'])}"
                        for f in flagged
                    )[:2000],
                    remediation="Store secrets in AWS Secrets Manager or SSM Parameter Store.",
                    cwe=312,
                    tags=["cloud", "aws", "lambda", "secret", "credential"],
                ))
            else:
                findings.append(Finding(
                    title=f"Lambda functions enumerated ({len(functions)})",
                    severity=Severity.INFO,
                    target=target,
                    tags=["cloud", "aws", "lambda", "recon"],
                ))
        except Exception as exc:
            logger.debug("Lambda enumeration failed: %s", exc)
        return findings

    def _enumerate_ecr(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("ecr")
            repos = [r["repositoryName"] for r in client.describe_repositories().get("repositories", [])]
            inventory["ecr_repos"] = repos
            findings.append(Finding(
                title=f"ECR repositories enumerated ({len(repos)})",
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {r}" for r in repos[:30]),
                tags=["cloud", "aws", "ecr", "recon"],
            ))
        except Exception as exc:
            logger.debug("ECR enumeration failed: %s", exc)
        return findings

    def _enumerate_eks(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("eks")
            clusters = client.list_clusters().get("clusters", [])
            inventory["eks_clusters"] = clusters
            for cluster_name in clusters:
                desc = client.describe_cluster(name=cluster_name).get("cluster", {})
                public_access = desc.get("resourcesVpcConfig", {}).get("endpointPublicAccess", False)
                if public_access:
                    findings.append(Finding(
                        title=f"EKS cluster with public API endpoint: {cluster_name}",
                        description=(
                            f"The EKS cluster {cluster_name!r} has a publicly accessible "
                            "Kubernetes API server endpoint. Ensure it is restricted to "
                            "known CIDRs."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Cluster: {cluster_name}\nPublic endpoint: {desc.get('endpoint')}",
                        remediation="Restrict public access CIDRs or disable public endpoint access.",
                        cwe=284,
                        tags=["cloud", "aws", "eks", "kubernetes", "exposure"],
                    ))
        except Exception as exc:
            logger.debug("EKS enumeration failed: %s", exc)
        return findings

    def _enumerate_sagemaker(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("sagemaker")
            endpoints = [e["EndpointName"] for e in client.list_endpoints().get("Endpoints", [])]
            notebooks = [n["NotebookInstanceName"] for n in client.list_notebook_instances().get("NotebookInstances", [])]
            inventory["sagemaker_endpoints"] = endpoints
            inventory["sagemaker_notebooks"] = notebooks
            findings.append(Finding(
                title=f"SageMaker resources: {len(endpoints)} endpoints, {len(notebooks)} notebooks",
                severity=Severity.INFO,
                target=target,
                evidence=(
                    f"Endpoints: {', '.join(endpoints[:10])}\n"
                    f"Notebooks: {', '.join(notebooks[:10])}"
                ),
                tags=["cloud", "aws", "sagemaker", "ai-infra", "recon"],
            ))
        except Exception as exc:
            logger.debug("SageMaker enumeration failed: %s", exc)
        return findings

    def _enumerate_bedrock(self, target: Target, inventory: Dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = self._session.client("bedrock")
            models = [m["modelId"] for m in client.list_foundation_models().get("modelSummaries", [])]
            inventory["bedrock_models"] = models
            findings.append(Finding(
                title=f"Bedrock foundation models accessible ({len(models)})",
                description="Account has access to Amazon Bedrock foundation models.",
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {m}" for m in models[:20]),
                tags=["cloud", "aws", "bedrock", "ai-infra", "recon"],
            ))
        except Exception as exc:
            logger.debug("Bedrock enumeration failed: %s", exc)
        return findings
