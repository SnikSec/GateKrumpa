"""
RepoScout — dependency vulnerability and supply chain auditor.

Parses dependency manifests found in the repository and cross-references
them against the OSV.dev vulnerability database.

Supported manifest formats:
  - requirements.txt (Python)
  - pyproject.toml (Python — PEP 517/518)
  - package.json (Node.js)
  - Cargo.toml (Rust)
  - go.mod (Go)
  - Gemfile (Ruby)

Also stores parsed dependencies in ScanContext for use by
:class:`~krumpa.modelhunt.supply_chain_auditor.SupplyChainAuditor`.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.http_client import HttpClient
from krumpa.reposcout.repo_crawler import RepoData

logger = logging.getLogger("krumpa.reposcout.dependency_auditor")

_OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_SIZE = 50  # stay within OSV batch limits


class DependencyAuditor:
    """Parse dependency files and check for known CVEs via OSV.dev."""

    async def audit(
        self,
        repo_data: RepoData,
        target: Target,
        ctx: ScanContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Parse all dependency files found in the repo
        all_deps: List[Tuple[str, str, str]] = []  # (ecosystem, package, version_or_unknown)

        for path, content in repo_data.files.items():
            fname = path.split("/")[-1].lower()
            parsed = _parse_manifest(fname, content)
            all_deps.extend(parsed)

        if not all_deps:
            return findings

        # Deduplicate
        unique_deps = list({(eco, pkg, ver) for eco, pkg, ver in all_deps})

        # Store in context for modelhunt supply chain auditor
        ctx.metadata["discovered_dependencies"] = [pkg for _, pkg, _ in unique_deps]
        ctx.metadata["requirements_txt"] = repo_data.files.get(
            "requirements.txt",
            repo_data.files.get("requirements-dev.txt", ""),
        )

        # Query OSV.dev in batches
        client = HttpClient(timeout=20.0, retries=2)
        try:
            vulnerabilities = await _query_osv(client, unique_deps)
        finally:
            await client.close()

        # Build findings
        if vulnerabilities:
            for vuln_info in vulnerabilities:
                pkg_name = vuln_info.get("package", "")
                vuln_ids = vuln_info.get("vulns", [])
                if not vuln_ids:
                    continue

                severity = _assess_severity(vuln_ids)
                findings.append(Finding(
                    title=f"Vulnerable dependency: {pkg_name} ({len(vuln_ids)} CVE(s))",
                    description=(
                        f"Package {pkg_name!r} in repository {repo_data.org}/{repo_data.repo} "
                        f"has {len(vuln_ids)} known vulnerability/vulnerabilities in the OSV database."
                    ),
                    severity=severity,
                    target=target,
                    evidence=(
                        f"Package: {pkg_name}\n"
                        f"Vulnerabilities: {', '.join(v.get('id', '?') for v in vuln_ids[:5])}"
                    ),
                    remediation=f"Upgrade {pkg_name!r} to a version without known CVEs.",
                    cwe=1357,
                    tags=["repo", "dependency", "cve", "supply-chain"],
                ))

        return findings


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_manifest(filename: str, content: str) -> List[Tuple[str, str, str]]:
    if filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        return _parse_requirements_txt(content)
    if filename == "pyproject.toml":
        return _parse_pyproject_toml(content)
    if filename in ("package.json",):
        return _parse_package_json(content)
    if filename == "cargo.toml":
        return _parse_cargo_toml(content)
    if filename == "go.mod":
        return _parse_go_mod(content)
    if filename in ("gemfile",):
        return _parse_gemfile(content)
    return []


def _parse_requirements_txt(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        # package==1.0 / package>=1.0 / package
        m = re.match(r"([A-Za-z0-9_\-\.]+)\s*(?:[=><!~]+\s*([\S]+))?", line)
        if m:
            pkg, ver = m.group(1), m.group(2) or "unknown"
            deps.append(("PyPI", pkg, ver))
    return deps


def _parse_pyproject_toml(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r'"([A-Za-z0-9_\-\.]+)\s*(?:[=><!~]+\s*([\S]+))?"', content):
        pkg, ver = m.group(1), m.group(2) or "unknown"
        if pkg and not pkg.startswith("python"):
            deps.append(("PyPI", pkg, ver))
    return deps


def _parse_package_json(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver in data.get(section, {}).items():
                ver_clean = re.sub(r"[^0-9.]", "", ver)
                deps.append(("npm", pkg, ver_clean or "unknown"))
    except Exception:
        pass
    return deps


def _parse_cargo_toml(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r'^(\w[\w\-_]+)\s*=\s*["\']?([\d\.]+)', content, re.MULTILINE):
        deps.append(("crates.io", m.group(1), m.group(2)))
    return deps


def _parse_go_mod(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r"^\s*([\w./\-]+)\s+(v[\d\.]+)", content, re.MULTILINE):
        deps.append(("Go", m.group(1), m.group(2)))
    return deps


def _parse_gemfile(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r"""gem\s+['"]([A-Za-z0-9_\-]+)['"]\s*,?\s*['"]?([\d\.~><!=\s]+)?['"]?""", content):
        deps.append(("RubyGems", m.group(1), m.group(2) or "unknown"))
    return deps


# ---------------------------------------------------------------------------
# OSV.dev integration
# ---------------------------------------------------------------------------

async def _query_osv(
    client: HttpClient,
    deps: List[Tuple[str, str, str]],
) -> List[Dict]:
    """Query OSV.dev for vulnerabilities in *deps*.  Returns enriched records."""
    ecosystem_map = {
        "PyPI": "PyPI", "npm": "npm", "crates.io": "crates.io",
        "Go": "Go", "RubyGems": "RubyGems",
    }
    results: List[Dict] = []

    # Chunk into batches
    for i in range(0, len(deps), _OSV_BATCH_SIZE):
        batch = deps[i : i + _OSV_BATCH_SIZE]
        queries = []
        for ecosystem, pkg, ver in batch:
            eco = ecosystem_map.get(ecosystem, ecosystem)
            q: Dict = {"package": {"name": pkg, "ecosystem": eco}}
            if ver and ver != "unknown":
                q["version"] = ver.lstrip("v")
            queries.append(q)

        try:
            resp = await client.request(
                "POST", _OSV_QUERY_URL,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"queries": queries}),
            )
            text = getattr(resp, "text", "") or ""
            data = json.loads(text)
        except Exception as exc:
            logger.debug("OSV.dev query failed: %s", exc)
            continue

        for idx, result in enumerate(data.get("results", [])):
            vulns = result.get("vulns", [])
            if vulns and idx < len(batch):
                _, pkg_name, _ = batch[idx]
                results.append({"package": pkg_name, "vulns": vulns})

    return results


def _assess_severity(vulns: List[Dict]) -> Severity:
    """Return the highest severity across a list of OSV vulnerability records."""
    severities = []
    for v in vulns:
        for severity_rec in v.get("severity", []):
            score = severity_rec.get("score", "")
            if score:
                try:
                    n = float(score)
                    if n >= 9.0:
                        return Severity.CRITICAL
                    elif n >= 7.0:
                        severities.append("high")
                    elif n >= 4.0:
                        severities.append("medium")
                    else:
                        severities.append("low")
                except ValueError:
                    pass
    if "high" in severities:
        return Severity.HIGH
    if "medium" in severities:
        return Severity.MEDIUM
    return Severity.LOW
