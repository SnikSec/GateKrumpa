"""
RepoScout — repository targeting and supply chain analysis module.

Handles ``github://`` and ``gitlab://`` scheme targets.  Uses PyGithub /
python-gitlab directly — never touches :class:`~krumpa.core.http_client.HttpClient`
for the repository enumeration itself (the HTTP client is used only for
auxiliary web checks).

Requires the ``[repo]`` optional dependency group:
    pip install gatekrumpa[repo]

If the required library is not installed the module logs a warning and
exits gracefully.
"""

from __future__ import annotations

import logging
from typing import List

from krumpa.core import BaseModule, Finding, ScanContext, TargetType

logger = logging.getLogger("krumpa.reposcout")


class RepoScoutModule(BaseModule):
    """Repository targeting — secret scanning, dependency auditing, CI/CD
    pipeline analysis, and MLOps configuration exposure."""

    name = "reposcout"
    description = (
        "Repository targeting — secrets, vulnerable dependencies, "
        "insecure CI/CD pipelines, and exposed ML/AI pipeline configurations"
    )
    dependencies: List[str] = []  # runs in parallel

    def __init__(self) -> None:
        super().__init__()

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        repo_targets = [
            t for t in ctx.targets
            if t.target_type in (TargetType.GITHUB, TargetType.GITLAB)
        ]
        if not repo_targets:
            logger.debug("No github:// or gitlab:// targets found — reposcout skipped")
            return []

        from krumpa.reposcout.repo_crawler import RepoCrawler
        from krumpa.reposcout.secret_scanner import SecretScanner
        from krumpa.reposcout.dependency_auditor import DependencyAuditor
        from krumpa.reposcout.pipeline_analyzer import PipelineAnalyzer
        from krumpa.reposcout.mlops_scanner import MlopsScanner

        for target in repo_targets:
            token = target.metadata.get("repo_token", "")
            provider = target.target_type

            logger.info(
                "RepoScout: scanning %s (%s)",
                target.url, provider.value,
            )

            try:
                crawler = RepoCrawler(token=token, provider=provider)
                repo_data = await crawler.crawl(target)
                if repo_data is None:
                    logger.warning("RepoScout: could not access %s", target.url)
                    continue

                # Store repo inventory in context for supply chain auditor (modelhunt)
                ctx.metadata.setdefault("repo_inventory", {})[target.url] = repo_data

                # Secret scanning
                scanner = SecretScanner()
                findings.extend(scanner.scan(repo_data, target))

                # Dependency auditing
                dep_auditor = DependencyAuditor()
                findings.extend(await dep_auditor.audit(repo_data, target, ctx))

                # CI/CD pipeline analysis
                pipeline = PipelineAnalyzer()
                findings.extend(pipeline.analyze(repo_data, target))

                # MLOps configuration scanning
                mlops = MlopsScanner()
                findings.extend(mlops.scan(repo_data, target))

            except Exception as exc:
                logger.warning("RepoScout failed for %s: %s", target.url, exc)

        for f in findings:
            self.add_finding(f)
        return findings
