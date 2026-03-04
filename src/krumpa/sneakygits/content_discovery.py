"""
SneakyGits — Content / directory discovery.

Brute-force common paths (admin panels, debug endpoints, backup files)
from a configurable wordlist to find hidden or unlinked resources.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional, Set

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.content_discovery")


# ------------------------------------------------------------------
# Default wordlist — most productive paths (~150 entries)
# ------------------------------------------------------------------

DEFAULT_WORDLIST: List[str] = [
    # Admin / management
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-login.php", "/cpanel", "/phpmyadmin", "/adminer",
    "/manage", "/management", "/console", "/dashboard", "/panel",
    # API / debug
    "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/debug", "/debug/vars", "/debug/pprof", "/_debug",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/metrics", "/health", "/healthcheck", "/status", "/info",
    "/.env", "/env", "/config", "/configuration", "/settings",
    # Source / version control
    "/.git", "/.git/HEAD", "/.git/config", "/.svn", "/.svn/entries",
    "/.hg", "/.bzr", "/.gitignore", "/.gitattributes",
    # Backup / temp
    "/backup", "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/site.tar.gz",
    "/web.config", "/web.config.bak", "/web.config.old",
    "/.htaccess", "/.htpasswd", "/server-status", "/server-info",
    # Common files
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/favicon.ico", "/humans.txt",
    # Error / trace
    "/error", "/errors", "/trace", "/elmah.axd", "/errorlog",
    "/phpinfo.php", "/test.php", "/info.php",
    # Common frameworks
    "/wp-content", "/wp-includes", "/wp-json",
    "/rails/info", "/rails/mailers",
    "/laravel", "/telescope",
    "/spring", "/spring-boot",
    "/__docroot__", "/__routes__",
    # Auth endpoints
    "/login", "/logout", "/register", "/signup", "/signin",
    "/forgot-password", "/reset-password", "/change-password",
    "/oauth", "/oauth/authorize", "/oauth/token",
    "/sso", "/saml", "/cas",
    # Misc
    "/cgi-bin", "/cgi-bin/", "/server", "/test", "/temp", "/tmp",
    "/upload", "/uploads", "/files", "/media", "/static",
    "/assets", "/public", "/private", "/internal",
    "/api/internal", "/api/admin", "/api/debug",
    # Cloud metadata
    "/latest/meta-data", "/metadata",
]


@dataclass
class DiscoveryResult(HttpClientMixin):
    """A single discovered path and its response metadata."""
    url: str
    status_code: int
    content_length: int = 0
    content_type: str = ""
    redirect_url: str = ""
    interesting: bool = False


class ContentDiscovery(HttpClientMixin):
    """
    Brute-force common paths against a target host and report
    any that return non-404 responses.
    """

    # Status codes that indicate "found"
    _FOUND_CODES: Set[int] = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}
    # Status codes that are especially interesting (auth-required, server error)
    _INTERESTING_CODES: Set[int] = {401, 403, 500}

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        wordlist: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        follow_redirects: bool = False,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._wordlist = wordlist or DEFAULT_WORDLIST
        self._extensions = extensions or []
        self._follow_redirects = follow_redirects

    async def discover(self, target: Target) -> List[Finding]:
        """Probe all wordlist paths against *target* and return findings."""
        findings: List[Finding] = []
        results = await self._probe_all(target)

        # Group results by category
        sensitive: List[DiscoveryResult] = []
        auth_required: List[DiscoveryResult] = []
        server_errors: List[DiscoveryResult] = []
        other_found: List[DiscoveryResult] = []

        for r in results:
            if self._is_sensitive_path(r.url):
                sensitive.append(r)
            elif r.status_code in (401, 403):
                auth_required.append(r)
            elif r.status_code >= 500:
                server_errors.append(r)
            elif r.status_code in self._FOUND_CODES:
                other_found.append(r)

        if sensitive:
            paths = ", ".join(r.url for r in sensitive[:10])
            findings.append(Finding(
                title=f"Sensitive paths discovered ({len(sensitive)})",
                description=f"Sensitive resources found: {paths}",
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(f"  {r.url} → {r.status_code}" for r in sensitive),
                remediation="Remove or restrict access to sensitive paths (.git, .env, admin panels, etc.).",
                cwe=538,
                tags=["recon", "content-discovery", "sensitive"],
            ))

        if auth_required:
            paths = ", ".join(r.url for r in auth_required[:10])
            findings.append(Finding(
                title=f"Protected paths found ({len(auth_required)})",
                description=f"Paths requiring authentication: {paths}",
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {r.url} → {r.status_code}" for r in auth_required),
                tags=["recon", "content-discovery", "auth-required"],
            ))

        if server_errors:
            paths = ", ".join(r.url for r in server_errors[:10])
            findings.append(Finding(
                title=f"Server errors on discovered paths ({len(server_errors)})",
                description=f"Paths returning 5xx errors: {paths}",
                severity=Severity.LOW,
                target=target,
                evidence="\n".join(f"  {r.url} → {r.status_code}" for r in server_errors),
                tags=["recon", "content-discovery", "error"],
            ))

        if other_found:
            paths = ", ".join(r.url for r in other_found[:20])
            findings.append(Finding(
                title=f"Additional paths discovered ({len(other_found)})",
                description=f"Accessible paths: {paths}",
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {r.url} → {r.status_code}" for r in other_found[:30]),
                tags=["recon", "content-discovery"],
            ))

        return findings

    @property
    def wordlist(self) -> List[str]:
        return list(self._wordlist)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _probe_all(self, target: Target) -> List[DiscoveryResult]:
        results: List[DiscoveryResult] = []
        base = target.url.rstrip("/")
        client = self._get_client()

        try:
            paths = list(self._wordlist)
            for ext in self._extensions:
                paths.extend(f"{p}{ext}" for p in self._wordlist if not p.endswith(ext))

            for path in paths:
                url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
                try:
                    resp = await client.request("GET", url)
                    code = getattr(resp, "status_code", 0)
                    if code in self._FOUND_CODES:
                        results.append(DiscoveryResult(
                            url=url,
                            status_code=code,
                            content_length=len(getattr(resp, "text", "") or ""),
                            content_type=getattr(resp, "headers", {}).get("content-type", ""),
                            interesting=code in self._INTERESTING_CODES,
                        ))
                except Exception:
                    pass  # network errors are expected for many paths
        finally:
            self._maybe_close(client)

        return results

    @staticmethod
    def _is_sensitive_path(url: str) -> bool:
        lower = url.lower()
        sensitive = [
            "/.git", "/.svn", "/.env", "/.htpasswd", "/.htaccess",
            "/backup", "/dump", "/database", "/phpmyadmin", "/adminer",
            "/actuator/env", "/debug", "server-status", "server-info",
            "/phpinfo", "/elmah", "/trace", "/web.config",
        ]
        return any(s in lower for s in sensitive)

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
