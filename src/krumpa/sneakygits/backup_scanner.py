"""
SneakyGits — Backup file scanner.

Probes for common backup/temp/old file patterns that leak source code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.backup_scanner")


# Common backup file suffixes & patterns
_BACKUP_PATTERNS: List[str] = [
    # Direct suffixes
    "{path}.bak", "{path}.old", "{path}.orig", "{path}.save",
    "{path}.tmp", "{path}.temp", "{path}.swp", "{path}~",
    "{path}.backup", "{path}.copy", "{path}.dist",
    # Editor backups
    "{path}.bkp", "#{path}#", ".{basename}.swp",
    # Version control
    "{path}.mine", "{path}.r1", "{path}.BASE", "{path}.LOCAL", "{path}.REMOTE",
    # Compressed dumps
    "{basename}.sql", "{basename}.sql.gz", "{basename}.tar.gz", "{basename}.zip",
    "backup.sql", "backup.zip", "dump.sql", "db.sql",
    # Config backups
    "web.config.bak", ".env.bak", ".env.old", ".env.production",
    ".htaccess.bak", "wp-config.php.bak", "config.php.bak",
    # IDE files
    ".idea/workspace.xml", ".vscode/settings.json",
    # Source archives
    "source.zip", "src.zip", "www.zip", "html.zip", "app.zip",
    "site.tar.gz", "backup.tar.gz",
]

# Paths to probe at the root
_ROOT_PROBES: List[str] = [
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.svn/wc.db",
    "/.hg/store/00manifest.i", "/.bzr/README",
    "/.DS_Store", "/Thumbs.db",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/server-info", "/server-status",
    "/phpinfo.php", "/info.php",
    "/elmah.axd", "/trace.axd",
    "/console", "/_debug",
]


@dataclass
class BackupFinding:
    """A single backup file discovery."""
    url: str
    status_code: int
    content_length: int = 0
    category: str = "backup"  # backup, vcs, config, debug


class BackupScanner(HttpClientMixin):
    """Scan for backup files, VCS artifacts, and debug endpoints."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def scan(self, target: Target) -> List[Finding]:
        """Scan a target for backup files and artifacts."""
        if not self._client:
            return []

        findings: List[Finding] = []
        discovered: List[BackupFinding] = []

        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        basename = path.split("/")[-1] if "/" in path else "index"

        # Check backup patterns
        probed: set = set()
        for pattern in _BACKUP_PATTERNS:
            probe_path = pattern.format(path=path, basename=basename)
            if not probe_path.startswith("/"):
                probe_path = "/" + probe_path
            if probe_path in probed:
                continue
            probed.add(probe_path)

            result = await self._probe(base + probe_path)
            if result:
                discovered.append(result)

        # Check root probes
        for probe_path in _ROOT_PROBES:
            if probe_path in probed:
                continue
            probed.add(probe_path)
            result = await self._probe(base + probe_path)
            if result:
                discovered.append(result)

        # Convert to findings
        if discovered:
            vcs = [d for d in discovered if d.category == "vcs"]
            backups = [d for d in discovered if d.category == "backup"]
            configs = [d for d in discovered if d.category == "config"]
            debug = [d for d in discovered if d.category == "debug"]

            if vcs:
                findings.append(Finding(
                    title=f"Version control artifacts exposed ({len(vcs)} files)",
                    description=f"VCS artifacts found: {', '.join(d.url for d in vcs[:5])}",
                    severity=Severity.HIGH,
                    target=target,
                    evidence="\n".join(f"{d.url} ({d.status_code})" for d in vcs),
                    remediation="Block access to .git, .svn, .hg directories in the web server config.",
                    cwe=538,
                    tags=["backup", "vcs", "information-disclosure"],
                ))

            if backups:
                findings.append(Finding(
                    title=f"Backup files exposed ({len(backups)} files)",
                    description=f"Backup files found: {', '.join(d.url for d in backups[:5])}",
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence="\n".join(f"{d.url} ({d.status_code})" for d in backups),
                    remediation="Remove backup files from production servers. Configure web server to block .bak, .old, .tmp extensions.",
                    cwe=530,
                    tags=["backup", "information-disclosure"],
                ))

            if configs:
                findings.append(Finding(
                    title=f"Configuration files exposed ({len(configs)} files)",
                    description=f"Config files found: {', '.join(d.url for d in configs[:5])}",
                    severity=Severity.HIGH,
                    target=target,
                    evidence="\n".join(f"{d.url} ({d.status_code})" for d in configs),
                    remediation="Block access to configuration files and environment files.",
                    cwe=538,
                    tags=["config", "information-disclosure"],
                ))

            if debug:
                findings.append(Finding(
                    title=f"Debug endpoints accessible ({len(debug)} endpoints)",
                    description=f"Debug endpoints found: {', '.join(d.url for d in debug[:5])}",
                    severity=Severity.HIGH,
                    target=target,
                    evidence="\n".join(f"{d.url} ({d.status_code})" for d in debug),
                    remediation="Disable debug endpoints in production.",
                    cwe=489,
                    tags=["debug", "information-disclosure"],
                ))

        return findings

    async def _probe(self, url: str) -> Optional[BackupFinding]:
        """Probe a single URL and return a finding if it exists."""
        if not self._client:
            return None
        try:
            resp = await self._client.request(method="GET", url=url)
            if resp.status_code < 400 and resp.status_code != 301:
                content_length = len(resp.text) if hasattr(resp, 'text') else 0
                if content_length > 0:
                    category = self._categorize(url)
                    return BackupFinding(
                        url=url,
                        status_code=resp.status_code,
                        content_length=content_length,
                        category=category,
                    )
        except Exception:
            pass
        return None

    @staticmethod
    def _categorize(url: str) -> str:
        lower = url.lower()
        if any(vcs in lower for vcs in ("/.git/", "/.svn/", "/.hg/", "/.bzr/")):
            return "vcs"
        if any(cfg in lower for cfg in (".env", "config", "web.config", ".htaccess", "wp-config")):
            return "config"
        if any(dbg in lower for dbg in ("phpinfo", "debug", "console", "trace.axd", "elmah", "server-status", "server-info")):
            return "debug"
        return "backup"
