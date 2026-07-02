"""
RepoScout — repository crawler.

Uses PyGithub (GitHub) and python-gitlab (GitLab) to enumerate repositories,
branches, commits, file trees, and CI/CD configuration files.

Returns a :class:`RepoData` dict consumed by all other reposcout analyzers.
Gracefully handles missing libraries, API rate limits, and private repos.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from krumpa.core import Target, TargetType

logger = logging.getLogger("krumpa.reposcout.repo_crawler")


@dataclass
class RepoData:
    """Collected repository data for analysis."""
    provider: str = ""
    org: str = ""
    repo: str = ""
    default_branch: str = "main"
    # File path → content (text) for files we explicitly retrieve
    files: Dict[str, str] = field(default_factory=dict)
    # List of (path, blob_sha) tuples for the full file tree (name only)
    tree: List[tuple] = field(default_factory=list)
    # workflow file paths
    workflow_files: List[str] = field(default_factory=list)
    # CI/CD file paths (gitlab-ci.yml etc)
    ci_files: List[str] = field(default_factory=list)
    # Package manifest paths discovered
    manifest_files: List[str] = field(default_factory=list)
    # Recent commit messages (for context)
    recent_commits: List[str] = field(default_factory=list)
    # Raw metadata dict from the provider API
    meta: Dict[str, Any] = field(default_factory=dict)


# File patterns we always fetch content for
_CONTENT_TARGETS = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "Cargo.toml", "go.mod", "Gemfile", "Gemfile.lock",
    "Pipfile", "Pipfile.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.example", ".env.sample",
    "dvc.yaml", "dvc.lock", "params.yaml",
    "config.yaml", "config.yml", "config.json",
    "mlflow.yaml", "wandb.yaml",
})

_CI_PATTERNS = frozenset({".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", "azure-pipelines.yml"})


class RepoCrawler:
    """Crawl a GitHub or GitLab repository and collect file metadata and content."""

    def __init__(self, *, token: str = "", provider: TargetType = TargetType.GITHUB) -> None:
        self._token = token
        self._provider = provider

    async def crawl(self, target: Target) -> Optional[RepoData]:
        """Return :class:`RepoData` for the target repository, or None on failure."""
        org_repo = _parse_repo(target.url)
        if not org_repo:
            logger.warning("Could not parse repo from URL: %s", target.url)
            return None

        org, repo_name = org_repo

        if self._provider == TargetType.GITHUB:
            return await self._crawl_github(org, repo_name, target)
        elif self._provider == TargetType.GITLAB:
            return await self._crawl_gitlab(org, repo_name, target)
        return None

    # ------------------------------------------------------------------
    # GitHub
    # ------------------------------------------------------------------

    async def _crawl_github(self, org: str, repo_name: str, target: Target) -> Optional[RepoData]:
        try:
            from github import Github, GithubException, Auth
        except ImportError:
            logger.warning(
                "PyGithub not installed — reposcout GitHub support disabled. "
                "Install with: pip install gatekrumpa[repo]"
            )
            return None

        try:
            auth = Auth.Token(self._token) if self._token else None
            gh = Github(auth=auth)
            repo = gh.get_repo(f"{org}/{repo_name}")
        except Exception as exc:
            logger.warning("GitHub repo access failed for %s/%s: %s", org, repo_name, exc)
            return None

        data = RepoData(
            provider="github",
            org=org,
            repo=repo_name,
            default_branch=repo.default_branch,
            meta={
                "full_name": repo.full_name,
                "private": repo.private,
                "stars": repo.stargazers_count,
                "description": repo.description,
                "topics": repo.get_topics(),
                "language": repo.language,
            },
        )

        # File tree
        try:
            contents = repo.get_git_tree(repo.default_branch, recursive=True)
            for item in contents.tree:
                data.tree.append((item.path, item.sha))
                fname = item.path.split("/")[-1].lower()
                if fname in _CONTENT_TARGETS:
                    data.manifest_files.append(item.path)
                if item.path.startswith(".github/workflows/") and item.path.endswith((".yml", ".yaml")):
                    data.workflow_files.append(item.path)
                if fname in _CI_PATTERNS:
                    data.ci_files.append(item.path)
        except Exception as exc:
            logger.debug("GitHub tree fetch failed: %s", exc)

        # Fetch content of important files
        for path in list(data.manifest_files) + list(data.workflow_files) + list(data.ci_files):
            try:
                content = repo.get_contents(path)
                if hasattr(content, "decoded_content"):
                    data.files[path] = content.decoded_content.decode("utf-8", errors="replace")
            except Exception:
                pass

        # Recent commits
        try:
            for commit in repo.get_commits()[:10]:
                data.recent_commits.append(commit.commit.message.split("\n")[0])
        except Exception:
            pass

        logger.info(
            "GitHub: crawled %s/%s — %d files, %d workflows",
            org, repo_name, len(data.tree), len(data.workflow_files),
        )
        return data

    # ------------------------------------------------------------------
    # GitLab
    # ------------------------------------------------------------------

    async def _crawl_gitlab(self, org: str, repo_name: str, target: Target) -> Optional[RepoData]:
        try:
            import gitlab
        except ImportError:
            logger.warning(
                "python-gitlab not installed — reposcout GitLab support disabled. "
                "Install with: pip install gatekrumpa[repo]"
            )
            return None

        # Parse GitLab instance URL from the target (gitlab://host/group/repo)
        parsed = urlparse(target.url)
        host = parsed.hostname or "gitlab.com"
        gl_url = f"https://{host}"

        try:
            gl = gitlab.Gitlab(gl_url, private_token=self._token or None)
            project = gl.projects.get(f"{org}/{repo_name}")
        except Exception as exc:
            logger.warning("GitLab project access failed for %s/%s: %s", org, repo_name, exc)
            return None

        data = RepoData(
            provider="gitlab",
            org=org,
            repo=repo_name,
            default_branch=project.default_branch or "main",
            meta={
                "full_name": project.path_with_namespace,
                "private": project.visibility == "private",
                "description": project.description,
            },
        )

        # File tree
        try:
            for item in project.repository_tree(recursive=True, all=True, as_list=True):
                if item["type"] == "blob":
                    path = item["path"]
                    data.tree.append((path, item.get("id", "")))
                    fname = path.split("/")[-1].lower()
                    if fname in _CONTENT_TARGETS:
                        data.manifest_files.append(path)
                    if fname == ".gitlab-ci.yml" or path.endswith((".yml", ".yaml")) and "ci" in path.lower():
                        data.ci_files.append(path)
        except Exception as exc:
            logger.debug("GitLab tree fetch failed: %s", exc)

        # Fetch content for manifest and CI files
        for path in list(data.manifest_files) + list(data.ci_files):
            try:
                content = project.files.get(file_path=path, ref=data.default_branch)
                data.files[path] = content.decode().decode("utf-8", errors="replace")
            except Exception:
                pass

        logger.info(
            "GitLab: crawled %s/%s — %d files",
            org, repo_name, len(data.tree),
        )
        return data


def _parse_repo(url: str) -> Optional[tuple]:
    """Extract (org, repo) from a github:// or gitlab:// URL."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lstrip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        # hostname may also carry the org for single-level paths
        if parsed.hostname and parts:
            return parsed.hostname, parts[0]
    except Exception:
        pass
    return None
