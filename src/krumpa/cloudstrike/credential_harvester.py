"""
CloudStrike — Cloud credential harvesting.

Scans EC2 userdata, Lambda environment variables, ECS task definitions,
and SSM Parameter Store for exposed credentials.

Evidence in findings contains the resource path and key name — never the
secret value itself.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.credential_harvester")

# Patterns that indicate a credential value (checked against env var keys + userdata)
_CREDENTIAL_KEY_PATTERNS = [
    re.compile(r"password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key|credential", re.IGNORECASE),
]
_AWS_KEY_PATTERN = re.compile(r"(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}")
_GENERIC_SECRET_PATTERN = re.compile(r"[A-Za-z0-9/+=]{40}")


class CredentialHarvester:
    """Scan cloud resource configurations for exposed credentials."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory = ctx.metadata.get("aws_inventory", {})

        findings.extend(self._scan_ec2_userdata(target))
        findings.extend(self._scan_lambda_env(inventory, target))
        findings.extend(self._scan_ecs_tasks(target))
        findings.extend(self._scan_ssm_parameters(target))

        return findings

    # ------------------------------------------------------------------

    def _scan_ec2_userdata(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ec2 = self._session.client("ec2")
            resp = ec2.describe_instances()
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    instance_id = inst["InstanceId"]
                    try:
                        ud_resp = ec2.describe_instance_attribute(
                            InstanceId=instance_id, Attribute="userData"
                        )
                        userdata_b64 = ud_resp.get("UserData", {}).get("Value", "")
                        if not userdata_b64:
                            continue
                        userdata = base64.b64decode(userdata_b64).decode("utf-8", errors="replace")
                        hits = self._scan_text_for_credentials(userdata)
                        if hits:
                            findings.append(Finding(
                                title=f"Credentials in EC2 userdata: {instance_id}",
                                description=(
                                    f"EC2 instance {instance_id!r} userdata contains "
                                    "patterns suggesting hardcoded credentials. "
                                    "Userdata is accessible via IMDSv1/v2 and the EC2 API."
                                ),
                                severity=Severity.CRITICAL,
                                target=target,
                                evidence=f"Instance: {instance_id}\nMatched patterns: {', '.join(hits)}",
                                remediation=(
                                    "Remove credentials from userdata. Use IAM instance profiles "
                                    "and AWS Secrets Manager instead."
                                ),
                                cwe=312,
                                tags=["cloud", "aws", "ec2", "credential", "userdata"],
                            ))
                    except Exception as exc:
                        logger.debug("Userdata check failed for %s: %s", instance_id, exc)
        except Exception as exc:
            logger.debug("EC2 userdata scan failed: %s", exc)
        return findings

    def _scan_lambda_env(self, inventory: dict, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        lambda_client = self._session.client("lambda")
        for fn in inventory.get("lambda_functions", []):
            fn_name = fn["name"]
            try:
                config = lambda_client.get_function_configuration(FunctionName=fn_name)
                env = (config.get("Environment") or {}).get("Variables", {})
                sensitive_keys = [
                    k for k in env
                    if any(p.search(k) for p in _CREDENTIAL_KEY_PATTERNS)
                ]
                if sensitive_keys:
                    findings.append(Finding(
                        title=f"Sensitive env vars in Lambda function: {fn_name}",
                        description=(
                            f"Lambda function {fn_name!r} has environment variable keys "
                            "suggesting stored credentials. These are visible in plaintext "
                            "to anyone with lambda:GetFunctionConfiguration."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Function: {fn_name}\nSensitive keys: {', '.join(sensitive_keys)}",
                        remediation=(
                            "Move secrets to AWS Secrets Manager or SSM Parameter Store "
                            "and retrieve them at runtime."
                        ),
                        cwe=312,
                        tags=["cloud", "aws", "lambda", "credential", "env-var"],
                    ))
            except Exception as exc:
                logger.debug("Lambda env scan failed for %s: %s", fn_name, exc)
        return findings

    def _scan_ecs_tasks(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ecs = self._session.client("ecs")
            task_defs = ecs.list_task_definitions(status="ACTIVE").get("taskDefinitionArns", [])
            for arn in task_defs[:50]:  # cap to avoid excessive API calls
                try:
                    td = ecs.describe_task_definition(taskDefinition=arn).get("taskDefinition", {})
                    for container in td.get("containerDefinitions", []):
                        for env_entry in container.get("environment", []):
                            key = env_entry.get("name", "")
                            if any(p.search(key) for p in _CREDENTIAL_KEY_PATTERNS):
                                findings.append(Finding(
                                    title=f"Credential in ECS task definition: {td.get('family')}",
                                    description=(
                                        f"ECS task definition {td.get('family')!r} container "
                                        f"{container.get('name')!r} has a plaintext environment "
                                        "variable that may contain credentials."
                                    ),
                                    severity=Severity.HIGH,
                                    target=target,
                                    evidence=f"Task: {arn}\nContainer: {container.get('name')}\nKey: {key}",
                                    remediation="Use ECS secrets (Secrets Manager or SSM) instead of plaintext env vars.",
                                    cwe=312,
                                    tags=["cloud", "aws", "ecs", "credential"],
                                ))
                except Exception as exc:
                    logger.debug("ECS task definition scan failed for %s: %s", arn, exc)
        except Exception as exc:
            logger.debug("ECS task scan failed: %s", exc)
        return findings

    def _scan_ssm_parameters(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ssm = self._session.client("ssm")
            # Look for parameters with public or broadly-accessible policies
            paginator = ssm.get_paginator("describe_parameters")
            unencrypted: List[str] = []
            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    if param.get("Type") == "String":
                        name = param.get("Name", "")
                        if any(p.search(name) for p in _CREDENTIAL_KEY_PATTERNS):
                            unencrypted.append(name)
            if unencrypted:
                findings.append(Finding(
                    title=f"SSM parameters stored as plaintext String ({len(unencrypted)})",
                    description=(
                        "SSM Parameter Store parameters with credential-suggesting names "
                        "are stored as String type (unencrypted) rather than SecureString."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence="\n".join(f"  {p}" for p in unencrypted[:20]),
                    remediation="Convert sensitive parameters to SecureString type with KMS encryption.",
                    cwe=312,
                    tags=["cloud", "aws", "ssm", "credential", "unencrypted"],
                ))
        except Exception as exc:
            logger.debug("SSM parameter scan failed: %s", exc)
        return findings

    @staticmethod
    def _scan_text_for_credentials(text: str) -> List[str]:
        """Return list of matched credential pattern names found in text."""
        hits: List[str] = []
        if _AWS_KEY_PATTERN.search(text):
            hits.append("AWS access key")
        for pattern in _CREDENTIAL_KEY_PATTERNS:
            if pattern.search(text):
                hits.append("credential keyword")
                break
        return hits
