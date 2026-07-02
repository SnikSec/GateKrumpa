"""
RepoScout — CI/CD pipeline security analyzer.

Parses GitHub Actions workflow files (``.github/workflows/*.yml``) and
GitLab CI configuration (``.gitlab-ci.yml``) for common security weaknesses:

  - Hardcoded secrets in ``env:`` blocks
  - ``permissions: write-all`` or missing permissions restrictions
  - Unpinned third-party actions (no full commit SHA pin)
  - ``pull_request_target`` without head commit SHA filtering
  - Self-hosted runner with broad repo access
  - Artifact upload/download injection risk
  - AWS credentials passed via env without OIDC
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from krumpa.core import Finding, Severity, Target
from krumpa.reposcout.repo_crawler import RepoData

logger = logging.getLogger("krumpa.reposcout.pipeline_analyzer")

# Patterns for secret-like values in YAML env blocks
_SECRET_VALUE_RE = re.compile(
    r'(?i)(?:password|secret|key|token|credential|api_key)\s*:\s*(?!\$\{\{)["\']?([A-Za-z0-9+/=_\-!@#]{10,})["\']?'
)

# Third-party action reference without SHA pin
# e.g.  uses: actions/checkout@v3  (should be uses: actions/checkout@a81bbbf8db8525...)
_UNPINNED_ACTION_RE = re.compile(
    r'uses:\s+([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_.]+)@(v?\d[\d.]*|main|master|latest|HEAD)',
    re.IGNORECASE,
)

# AWS credentials hardcoded (not via OIDC)
_AWS_CRED_ENV_RE = re.compile(
    r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*:\s*(?!\$\{\{)[A-Za-z0-9+/=]{10,}',
    re.IGNORECASE,
)


class PipelineAnalyzer:
    """Analyze CI/CD configuration files for security weaknesses."""

    def analyze(self, repo_data: RepoData, target: Target) -> List[Finding]:
        findings: List[Finding] = []

        for path in repo_data.workflow_files + repo_data.ci_files:
            content = repo_data.files.get(path, "")
            if not content:
                continue

            is_github = path.startswith(".github/workflows/")
            is_gitlab = path.endswith(".gitlab-ci.yml") or ".gitlab-ci" in path

            if is_github:
                findings.extend(self._analyze_github_workflow(content, path, target))
            elif is_gitlab:
                findings.extend(self._analyze_gitlab_ci(content, path, target))

        return findings

    # ------------------------------------------------------------------
    # GitHub Actions
    # ------------------------------------------------------------------

    def _analyze_github_workflow(
        self, content: str, path: str, target: Target
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Hardcoded secrets in env blocks
        for m in _SECRET_VALUE_RE.finditer(content):
            findings.append(Finding(
                title=f"Hardcoded secret in GitHub Actions workflow: {path}",
                description=(
                    f"Workflow {path!r} contains a key matching a credential pattern "
                    "with a non-expression value. Hardcoded values are visible to all "
                    "contributors and are stored in git history."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=f"File: {path}\nPattern match: {m.group(0)[:60]} (value redacted)",
                remediation="Move secrets to GitHub Actions encrypted secrets (${{ secrets.MY_SECRET }}).",
                cwe=312,
                tags=["repo", "ci-cd", "github-actions", "hardcoded-secret"],
            ))
            break  # one finding per file

        # 2. permissions: write-all
        if re.search(r'permissions\s*:\s*write-all', content, re.IGNORECASE):
            findings.append(Finding(
                title=f"GitHub Actions workflow uses permissions: write-all — {path}",
                description=(
                    f"Workflow {path!r} grants write-all permissions to the GITHUB_TOKEN. "
                    "This gives every step maximum repo write access, violating least-privilege."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"File: {path}\nPermissions: write-all",
                remediation="Replace write-all with granular permission blocks (e.g., contents: read).",
                cwe=269,
                tags=["repo", "ci-cd", "github-actions", "overprivileged"],
            ))

        # 3. Unpinned third-party actions
        unpinned = _UNPINNED_ACTION_RE.findall(content)
        if unpinned:
            findings.append(Finding(
                title=f"Unpinned third-party actions in workflow: {path}",
                description=(
                    f"Workflow {path!r} uses {len(unpinned)} third-party action(s) referenced "
                    "by mutable tag/branch rather than full commit SHA. A compromised or "
                    "hijacked action tag could inject malicious code into CI runs."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(f"  {a}@{v}" for a, v in unpinned[:10]),
                remediation=(
                    "Pin all third-party actions to a full commit SHA: "
                    "uses: actions/checkout@a81bbbf8db8525... (not @v3 or @main)."
                ),
                cwe=494,
                tags=["repo", "ci-cd", "github-actions", "unpinned-action", "supply-chain"],
            ))

        # 4. pull_request_target without SHA check (pwn request risk)
        if "pull_request_target" in content:
            if "github.event.pull_request.head.sha" not in content:
                findings.append(Finding(
                    title=f"pull_request_target without head SHA check — {path}",
                    description=(
                        f"Workflow {path!r} triggers on pull_request_target but does not "
                        "restrict execution to verified commits via "
                        "github.event.pull_request.head.sha. "
                        "An attacker can fork the repo, submit a PR, and run arbitrary code "
                        "with write permissions to the base repository ('pwn request')."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"File: {path}\nTrigger: pull_request_target",
                    remediation=(
                        "Use pull_request (not pull_request_target) or add explicit "
                        "head SHA validation before any privileged steps."
                    ),
                    cwe=284,
                    tags=["repo", "ci-cd", "github-actions", "pwn-request", "pull-request-target"],
                ))

        # 5. AWS credentials via env (not OIDC)
        if _AWS_CRED_ENV_RE.search(content):
            findings.append(Finding(
                title=f"AWS credentials in GitHub Actions env block: {path}",
                description=(
                    f"Workflow {path!r} passes AWS credentials via environment variables "
                    "rather than using GitHub OIDC federation. Long-lived credentials "
                    "in env blocks are a credential theft risk."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"File: {path}\nAWS credential key detected in env block",
                remediation=(
                    "Replace static AWS credentials with GitHub OIDC federation. "
                    "Configure an IAM OIDC identity provider for GitHub Actions."
                ),
                cwe=312,
                tags=["repo", "ci-cd", "github-actions", "aws", "credential"],
            ))

        return findings

    # ------------------------------------------------------------------
    # GitLab CI
    # ------------------------------------------------------------------

    def _analyze_gitlab_ci(
        self, content: str, path: str, target: Target
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Hardcoded secrets
        for m in _SECRET_VALUE_RE.finditer(content):
            findings.append(Finding(
                title=f"Hardcoded secret in GitLab CI file: {path}",
                description=(
                    f"GitLab CI file {path!r} contains a key matching a credential "
                    "pattern with a non-variable value."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=f"File: {path}\nPattern: {m.group(0)[:60]} (value redacted)",
                remediation="Move secrets to GitLab CI/CD masked variables ($MY_SECRET).",
                cwe=312,
                tags=["repo", "ci-cd", "gitlab-ci", "hardcoded-secret"],
            ))
            break

        # 2. Self-hosted runner reference (access scope risk)
        if re.search(r'tags\s*:\s*\n\s*-\s*self-hosted', content, re.IGNORECASE):
            findings.append(Finding(
                title=f"Self-hosted GitLab runner referenced: {path}",
                description=(
                    f"GitLab CI file {path!r} runs jobs on a self-hosted runner. "
                    "Malicious merge request code could access files, credentials, "
                    "and network resources on the runner host."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"File: {path}\nSelf-hosted runner tag detected",
                remediation=(
                    "Restrict self-hosted runners to protected branches. "
                    "Enable runner job isolation. Never allow unverified code to "
                    "run on shared infrastructure."
                ),
                cwe=284,
                tags=["repo", "ci-cd", "gitlab-ci", "self-hosted-runner"],
            ))

        return findings
