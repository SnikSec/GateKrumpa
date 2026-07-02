"""Tests for PipelineAnalyzer — CI/CD security analysis."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.reposcout.repo_crawler import RepoData
from krumpa.reposcout.pipeline_analyzer import PipelineAnalyzer


def _make_repo(workflow_files: dict | None = None, ci_files: dict | None = None) -> RepoData:
    data = RepoData(provider="github", org="test-org", repo="test-repo")
    if workflow_files:
        for path, content in workflow_files.items():
            data.workflow_files.append(path)
            data.files[path] = content
    if ci_files:
        for path, content in ci_files.items():
            data.ci_files.append(path)
            data.files[path] = content
    return data


_SAFE_WORKFLOW = """
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8db8525931397fef0f7a08ba9d7a6b2c5
"""


class TestPipelineAnalyzer:

    def _target(self) -> Target:
        return Target(url="github://test-org/test-repo")

    def test_detects_hardcoded_secret_in_env(self):
        workflow = """
name: Deploy
on: [push]
jobs:
  deploy:
    env:
      password: supersecretvalue123
    steps:
      - run: deploy.sh
"""
        repo = _make_repo(workflow_files={".github/workflows/deploy.yml": workflow})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        assert any("hardcoded secret" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_write_all_permissions(self):
        workflow = """
name: CI
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8db8525931397fef0f7a08ba9d7a6b2c5
"""
        repo = _make_repo(workflow_files={".github/workflows/ci.yml": workflow})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        assert any("write-all" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_unpinned_actions(self):
        workflow = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: echo hello
"""
        repo = _make_repo(workflow_files={".github/workflows/ci.yml": workflow})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        assert any("unpinned" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_detects_pull_request_target_without_sha(self):
        workflow = """
name: PR Check
on:
  pull_request_target:
    types: [opened]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.actor }}
"""
        repo = _make_repo(workflow_files={".github/workflows/pr.yml": workflow})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        assert any("pull_request_target" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_no_findings_for_safe_workflow(self):
        repo = _make_repo(workflow_files={".github/workflows/ci.yml": _SAFE_WORKFLOW})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical_high == []

    def test_detects_hardcoded_secret_in_gitlab_ci(self):
        gitlab_ci = """
stages:
  - deploy
deploy:
  stage: deploy
  variables:
    password: hardcodedpassword123
  script:
    - ./deploy.sh
"""
        repo = _make_repo(ci_files={".gitlab-ci.yml": gitlab_ci})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        assert any("gitlab" in f.title.lower() for f in findings)

    def test_empty_repo_returns_no_findings(self):
        repo = RepoData(provider="github", org="org", repo="repo")
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())
        assert findings == []

    def test_detects_aws_credentials_in_workflow(self):
        workflow = """
name: Deploy
on: [push]
jobs:
  deploy:
    env:
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
    steps:
      - run: aws s3 sync
"""
        repo = _make_repo(workflow_files={".github/workflows/deploy.yml": workflow})
        analyzer = PipelineAnalyzer()
        findings = analyzer.analyze(repo, self._target())

        aws_findings = [f for f in findings if "aws" in " ".join(f.tags)]
        assert len(aws_findings) >= 1
