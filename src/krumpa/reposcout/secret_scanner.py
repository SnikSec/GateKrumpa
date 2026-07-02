"""
RepoScout — secret scanner.

Scans repository file contents for hardcoded credentials and secrets,
reusing and extending the pattern library from
:mod:`krumpa.sneakygits.js_extractor`.

Evidence includes the file path and line number; the actual secret value
is always redacted in findings to prevent accidental secret propagation.
"""

from __future__ import annotations

import logging
import re
from typing import List, NamedTuple

from krumpa.core import Finding, Severity, Target
from krumpa.reposcout.repo_crawler import RepoData

logger = logging.getLogger("krumpa.reposcout.secret_scanner")


class _SecretPattern(NamedTuple):
    name: str
    regex: re.Pattern
    severity: Severity
    cwe: int
    tags: tuple


_SECRET_PATTERNS: List[_SecretPattern] = [
    _SecretPattern("AWS Access Key ID",   re.compile(r"(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}"),                                Severity.CRITICAL, 312, ("aws", "access-key")),
    _SecretPattern("AWS Secret Access Key", re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']?([A-Za-z0-9/+=]{40})["\']?'),    Severity.CRITICAL, 312, ("aws", "secret-key")),
    _SecretPattern("GCP API Key",          re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                                           Severity.CRITICAL, 312, ("gcp", "api-key")),
    _SecretPattern("GitHub Token",         re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),                                       Severity.CRITICAL, 312, ("github", "token")),
    _SecretPattern("Private SSH/TLS Key",  re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----"),          Severity.CRITICAL, 312, ("private-key", "ssh")),
    _SecretPattern("Generic API Key",      re.compile(r'''(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?'''), Severity.HIGH, 312, ("api-key",)),
    _SecretPattern("Generic Secret",       re.compile(r'''(?i)(?:secret|password|passwd|token)\s*[=:]\s*["']([^"'\s]{8,})["']'''), Severity.HIGH, 312, ("secret", "password")),
    _SecretPattern("Database URL",         re.compile(r"(?:postgres|mysql|mongodb|redis|mssql)://[^\s\"'<>]{10,}"),          Severity.HIGH,     312, ("database", "connection-string")),
    _SecretPattern("Slack Token",          re.compile(r"xox[bpors]-[0-9A-Za-z\-]+"),                                        Severity.HIGH,     312, ("slack", "token")),
    _SecretPattern("Stripe Secret Key",    re.compile(r"sk_live_[0-9A-Za-z]{24,}"),                                         Severity.CRITICAL, 312, ("stripe", "payment")),
    _SecretPattern("JWT Secret",           re.compile(r'''(?i)(?:jwt[_\-]?secret|secret[_\-]?key)\s*[=:]\s*["']([^"'\s]{10,})["']'''), Severity.HIGH, 312, ("jwt", "secret")),
    _SecretPattern("HuggingFace Token",    re.compile(r"hf_[A-Za-z0-9]{30,}"),                                              Severity.HIGH,     312, ("huggingface", "ai", "token")),
    _SecretPattern("OpenAI API Key",       re.compile(r"sk-[A-Za-z0-9]{32,}"),                                              Severity.CRITICAL, 312, ("openai", "ai", "api-key")),
    _SecretPattern("Anthropic API Key",    re.compile(r"sk-ant-[A-Za-z0-9\-_]{30,}"),                                       Severity.CRITICAL, 312, ("anthropic", "ai", "api-key")),
]

# File extensions to skip (binary, minified, lock files)
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".lock", ".sum",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe",
})

# Files that commonly contain secret-looking test/example values to skip
_EXAMPLE_PATHS = re.compile(
    r"(?i)(test|spec|example|sample|mock|fixture|fake|dummy|placeholder)",
)


class SecretScanner:
    """Scan repository files for hardcoded secrets and credentials."""

    def scan(self, repo_data: RepoData, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for path, content in repo_data.files.items():
            # Skip example/test files and binary extensions
            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in _SKIP_EXTENSIONS:
                continue

            for line_no, line in enumerate(content.splitlines(), start=1):
                for pattern in _SECRET_PATTERNS:
                    matches = pattern.regex.findall(line)
                    if not matches:
                        continue

                    # Skip test/example files with a lower confidence flag
                    is_example = bool(_EXAMPLE_PATHS.search(path))
                    severity = Severity.MEDIUM if is_example else pattern.severity

                    key = (pattern.name, path)
                    if key in seen:
                        continue
                    seen.add(key)

                    match_preview = str(matches[0])[:12] + "..." if matches else ""
                    findings.append(Finding(
                        title=f"Secret in repository: {pattern.name} in {path}",
                        description=(
                            f"{'Example/test file — verify manually. ' if is_example else ''}"
                            f"Found {pattern.name!r} pattern in {path!r}. "
                            "Hardcoded credentials are accessible to anyone with "
                            "repository read access and may remain in git history."
                        ),
                        severity=severity,
                        target=target,
                        evidence=(
                            f"File: {path}\n"
                            f"Line: {line_no}\n"
                            f"Pattern: {pattern.name}\n"
                            f"Match preview: {match_preview} (redacted)"
                        ),
                        remediation=(
                            "Remove the credential from the repository immediately. "
                            "Rotate the credential. Use git-filter-repo to purge from history. "
                            "Store secrets in a secrets manager or CI/CD vault."
                        ),
                        cwe=pattern.cwe,
                        tags=["repo", "secret", "credential"] + list(pattern.tags),
                    ))

        return findings
