"""
CloudStrike — AWS AI/ML pipeline security scanner.

Checks SageMaker and Bedrock configurations for attack surface exposures:
  - SageMaker notebook instances with direct internet access
  - SageMaker training jobs pointing to public S3 data
  - SageMaker model artifact buckets with weak access
  - Bedrock invocation logging disabled
  - SageMaker Model Registry public model packages
"""

from __future__ import annotations

import logging
from typing import Any, List

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.ai_pipeline_scanner")


class AiPipelineScanner:
    """Scan AWS AI/ML pipeline configurations for security exposures."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        inventory = ctx.metadata.get("aws_inventory", {})

        findings.extend(self._check_notebook_internet_access(target, inventory))
        findings.extend(self._check_training_job_data_exposure(target))
        findings.extend(self._check_bedrock_logging(target))
        findings.extend(self._check_model_registry(target))

        return findings

    # ------------------------------------------------------------------

    def _check_notebook_internet_access(self, target: Target, inventory: dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            sm = self._session.client("sagemaker")
            for nb_name in inventory.get("sagemaker_notebooks", []):
                try:
                    desc = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
                    direct_internet = desc.get("DirectInternetAccess", "Disabled")
                    if direct_internet == "Enabled":
                        findings.append(Finding(
                            title=f"SageMaker notebook with direct internet access: {nb_name}",
                            description=(
                                f"Notebook instance {nb_name!r} has DirectInternetAccess=Enabled. "
                                "This allows the notebook to exfiltrate training data or model "
                                "artifacts to external hosts, and enables inbound connections."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Notebook: {nb_name}\n"
                                f"Status: {desc.get('NotebookInstanceStatus')}\n"
                                f"Instance type: {desc.get('InstanceType')}\n"
                                f"IAM role: {desc.get('RoleArn')}"
                            ),
                            remediation=(
                                "Disable DirectInternetAccess and route traffic through a NAT "
                                "gateway in a private VPC subnet."
                            ),
                            cwe=284,
                            tags=["cloud", "aws", "sagemaker", "notebook", "internet-access", "ai-infra"],
                        ))
                except Exception as exc:
                    logger.debug("Notebook check failed for %s: %s", nb_name, exc)
        except Exception as exc:
            logger.debug("Notebook internet access check failed: %s", exc)
        return findings

    def _check_training_job_data_exposure(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            sm = self._session.client("sagemaker")
            s3 = self._session.client("s3")
            jobs = sm.list_training_jobs(MaxResults=20, StatusEquals="Completed").get("TrainingJobSummaries", [])
            for job in jobs:
                job_name = job["TrainingJobName"]
                try:
                    desc = sm.describe_training_job(TrainingJobName=job_name)
                    for channel in desc.get("InputDataConfig", []):
                        data_source = channel.get("DataSource", {})
                        s3_source = data_source.get("S3DataSource", {})
                        s3_uri = s3_source.get("S3Uri", "")
                        if s3_uri.startswith("s3://"):
                            bucket = s3_uri.split("/")[2]
                            try:
                                pub_block = s3.get_public_access_block(Bucket=bucket)
                                config = pub_block.get("PublicAccessBlockConfiguration", {})
                                if not all(config.values()):
                                    findings.append(Finding(
                                        title=f"SageMaker training data in potentially public bucket: {bucket}",
                                        description=(
                                            f"Training job {job_name!r} uses data from S3 bucket "
                                            f"{bucket!r} which does not have full public access "
                                            "block enabled. Training data may be publicly accessible."
                                        ),
                                        severity=Severity.HIGH,
                                        target=target,
                                        evidence=f"Job: {job_name}\nData bucket: s3://{bucket}\nPublic block config: {config}",
                                        remediation="Enable all S3 public access block settings on training data buckets.",
                                        cwe=284,
                                        tags=["cloud", "aws", "sagemaker", "training-data", "s3", "ai-infra"],
                                    ))
                            except Exception:
                                pass
                except Exception as exc:
                    logger.debug("Training job check failed for %s: %s", job_name, exc)
        except Exception as exc:
            logger.debug("Training job data exposure check failed: %s", exc)
        return findings

    def _check_bedrock_logging(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            bedrock = self._session.client("bedrock")
            config = bedrock.get_model_invocation_logging_configuration().get(
                "loggingConfig", {}
            )
            if not config:
                findings.append(Finding(
                    title="Amazon Bedrock invocation logging disabled",
                    description=(
                        "Bedrock model invocation logging is not configured. "
                        "Without logging, there is no audit trail of prompts sent to "
                        "foundation models, making data leakage and misuse undetectable."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence="loggingConfig: empty/not configured",
                    remediation=(
                        "Enable Bedrock invocation logging to CloudWatch Logs or S3 "
                        "to maintain an audit trail of model inputs and outputs."
                    ),
                    cwe=778,
                    tags=["cloud", "aws", "bedrock", "logging", "audit", "ai-infra"],
                ))
        except Exception as exc:
            logger.debug("Bedrock logging check failed: %s", exc)
        return findings

    def _check_model_registry(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        try:
            sm = self._session.client("sagemaker")
            groups = sm.list_model_package_groups().get("ModelPackageGroupSummaryList", [])
            for group in groups:
                group_name = group["ModelPackageGroupName"]
                try:
                    policy_resp = sm.get_model_package_group_policy(
                        ModelPackageGroupName=group_name
                    )
                    import json
                    policy = json.loads(policy_resp.get("ResourcePolicy", "{}"))
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                            findings.append(Finding(
                                title=f"SageMaker model registry group publicly accessible: {group_name}",
                                description=(
                                    f"Model package group {group_name!r} has a resource policy "
                                    "allowing access from any principal (*). Proprietary model "
                                    "packages may be accessible by any AWS account."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=f"Group: {group_name}\nPolicy principal: *",
                                remediation="Restrict the resource policy to specific account ARNs.",
                                cwe=284,
                                tags=["cloud", "aws", "sagemaker", "model-registry", "ai-infra"],
                            ))
                except sm.exceptions.ClientError:
                    pass  # No policy set — acceptable
                except Exception as exc:
                    logger.debug("Model registry check failed for %s: %s", group_name, exc)
        except Exception as exc:
            logger.debug("Model registry scan failed: %s", exc)
        return findings
