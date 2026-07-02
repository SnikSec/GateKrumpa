"""
CloudStrike — AWS environment attack surface analysis module.

Handles targets with the ``aws://`` URL scheme.  Uses ``boto3`` directly for
all AWS API calls; never touches :class:`~krumpa.core.http_client.HttpClient`.

Requires the ``[cloud]`` optional dependency group:
    pip install gatekrumpa[cloud]

If ``boto3`` is not installed the module logs a warning and exits gracefully
without producing an error.
"""

from __future__ import annotations

import logging
from typing import List

from krumpa.core import BaseModule, Finding, ScanContext, TargetType

logger = logging.getLogger("krumpa.cloudstrike")


class CloudStrikeModule(BaseModule):
    """AWS attack surface analysis — IAM paths, S3, credentials, AI pipelines."""

    name = "cloudstrike"
    description = (
        "Cloud attack surface — AWS IAM path analysis, S3 exposure, "
        "credential harvesting, and AI pipeline scanning"
    )
    dependencies: List[str] = []  # runs in parallel with sneakygits

    def __init__(self) -> None:
        super().__init__()

    async def run(self, ctx: ScanContext) -> List[Finding]:
        try:
            import boto3  # noqa: F401
        except ImportError:
            logger.warning(
                "boto3 not installed — cloudstrike module disabled. "
                "Install with: pip install gatekrumpa[cloud]"
            )
            return []

        findings: List[Finding] = []

        aws_targets = [t for t in ctx.targets if t.target_type == TargetType.AWS]
        if not aws_targets:
            logger.debug("No aws:// targets found — cloudstrike skipped")
            return []

        from krumpa.cloudstrike.aws_recon import AwsRecon
        from krumpa.cloudstrike.iam_pathfinder import IamPathfinder
        from krumpa.cloudstrike.s3_auditor import S3Auditor
        from krumpa.cloudstrike.metadata_service import MetadataServiceAnalyzer
        from krumpa.cloudstrike.credential_harvester import CredentialHarvester
        from krumpa.cloudstrike.data_exfiltration import DataExfiltrationAnalyzer
        from krumpa.cloudstrike.ai_pipeline_scanner import AiPipelineScanner

        for target in aws_targets:
            region = target.metadata.get("aws_region", "us-east-1")
            profile = target.metadata.get("aws_profile")

            session = _build_session(region=region, profile=profile)

            logger.info("CloudStrike: scanning AWS region %s (profile=%s)", region, profile or "default")

            for analyzer_cls in (
                AwsRecon,
                IamPathfinder,
                S3Auditor,
                MetadataServiceAnalyzer,
                CredentialHarvester,
                DataExfiltrationAnalyzer,
                AiPipelineScanner,
            ):
                try:
                    analyzer = analyzer_cls(session=session)
                    findings.extend(await analyzer.analyze(target, ctx))
                except Exception as exc:
                    logger.warning("%s failed: %s", analyzer_cls.__name__, exc)

        for f in findings:
            self.add_finding(f)
        return findings


def _build_session(*, region: str, profile: str | None):
    """Build a boto3 Session from profile / env / instance profile chain."""
    import boto3
    kwargs = {"region_name": region}
    if profile:
        kwargs["profile_name"] = profile
    return boto3.Session(**kwargs)
