"""
BossKey — OAuth2 flow analyser.

Inspects OAuth2 / OpenID Connect configurations for common security
weaknesses:

* Missing or weak ``state`` parameter (CSRF in OAuth)
* Permissive ``redirect_uri`` validation (open redirect)
* Implicit-grant usage (token in fragment — deprecated)
* ``PKCE`` absence on public clients
* Token endpoint TLS enforcement
* Scope over-granting
* Misconfigured ``/.well-known/openid-configuration``
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.oauth2")


# ---------------------------------------------------------------------------
# Well-known discovery paths
# ---------------------------------------------------------------------------

_WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class OAuth2Config(HttpClientMixin):
    """Parsed OAuth2 / OIDC server metadata."""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    issuer: str = ""
    response_types_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    code_challenge_methods_supported: List[str] = field(default_factory=list)
    scopes_supported: List[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OAuth2Config":
        return cls(
            authorization_endpoint=data.get("authorization_endpoint", ""),
            token_endpoint=data.get("token_endpoint", ""),
            issuer=data.get("issuer", ""),
            response_types_supported=data.get("response_types_supported", []),
            grant_types_supported=data.get("grant_types_supported", []),
            code_challenge_methods_supported=data.get("code_challenge_methods_supported", []),
            scopes_supported=data.get("scopes_supported", []),
            token_endpoint_auth_methods_supported=data.get(
                "token_endpoint_auth_methods_supported", []
            ),
            raw=data,
        )


# ---------------------------------------------------------------------------
# OAuth2Analyzer
# ---------------------------------------------------------------------------

class OAuth2Analyzer(HttpClientMixin):
    """Analyse OAuth2 / OIDC configurations for security weaknesses.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    """

    def __init__(
        self, *, http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Discover and analyse OAuth2 configuration for *target*."""
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            findings: List[Finding] = []

            # 1. Try well-known discovery
            config = await self._discover_config(client, target)
            if config:
                findings.extend(self._check_config(config, target))

            # 2. Probe authorize endpoint for common issues
            if config and config.authorization_endpoint:
                findings.extend(
                    await self._check_authorize_endpoint(
                        client, config, target,
                    )
                )

            # 3. Check token endpoint TLS
            if config and config.token_endpoint:
                findings.extend(self._check_token_tls(config, target))

            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def _discover_config(
        self, client: HttpClient, target: Target,
    ) -> Optional[OAuth2Config]:
        """Try well-known URLs to fetch OAuth2 / OIDC metadata."""
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _WELL_KNOWN_PATHS:
            url = base + path
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = json.loads(resp.text)
                    if isinstance(data, dict) and (
                        "authorization_endpoint" in data or "token_endpoint" in data
                    ):
                        logger.info("Discovered OAuth2 config at %s", url)
                        return OAuth2Config.from_dict(data)
            except (httpx.HTTPError, OSError, json.JSONDecodeError):
                continue

        # Also check metadata provided in ctx or target metadata
        meta_config = target.metadata.get("oauth2_config")
        if isinstance(meta_config, dict):
            return OAuth2Config.from_dict(meta_config)

        return None

    # ------------------------------------------------------------------
    # Configuration checks
    # ------------------------------------------------------------------

    def _check_config(
        self, config: OAuth2Config, target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Implicit grant (response_type=token) — deprecated by OAuth 2.1
        if "token" in config.response_types_supported:
            findings.append(Finding(
                title="OAuth2 implicit grant (response_type=token) supported",
                description=(
                    "The authorization server supports the implicit grant flow, "
                    "which exposes access tokens in the URL fragment. This flow "
                    "is deprecated by OAuth 2.1 due to token leakage risks."
                ),
                severity=Severity.HIGH,
                target=target,
                remediation=(
                    "Disable the implicit grant. Use authorization code + PKCE instead."
                ),
                cwe=522,
                tags=["auth", "oauth2", "implicit-grant"],
            ))

        # 2. No PKCE support
        if not config.code_challenge_methods_supported:
            findings.append(Finding(
                title="OAuth2 server does not advertise PKCE support",
                description=(
                    "The authorization server metadata does not include "
                    "code_challenge_methods_supported. PKCE (RFC 7636) prevents "
                    "authorization code interception attacks."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Enable PKCE and advertise S256 in the metadata.",
                cwe=311,
                tags=["auth", "oauth2", "no-pkce"],
            ))
        elif "S256" not in config.code_challenge_methods_supported:
            # Only 'plain' advertised — weak
            findings.append(Finding(
                title="OAuth2 PKCE only supports 'plain' method",
                description=(
                    "The server advertises PKCE but only with the 'plain' challenge "
                    "method. S256 should be used; 'plain' provides no protection "
                    "against interception."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Support the S256 code_challenge_method.",
                cwe=311,
                tags=["auth", "oauth2", "pkce-plain"],
            ))

        # 3. Password grant supported
        if "password" in config.grant_types_supported:
            findings.append(Finding(
                title="OAuth2 resource owner password grant supported",
                description=(
                    "The server supports the password grant (ROPC), which requires "
                    "sending user credentials directly to the token endpoint. "
                    "This grant type is deprecated by OAuth 2.1."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Disable the password grant type.",
                cwe=522,
                tags=["auth", "oauth2", "password-grant"],
            ))

        # 4. Overly broad scopes
        dangerous_scopes = {"admin", "root", "superuser", "*", "all"}
        broad_scopes = set(config.scopes_supported) & dangerous_scopes
        if broad_scopes:
            findings.append(Finding(
                title=f"OAuth2 server exposes dangerous scopes: {', '.join(broad_scopes)}",
                description=(
                    "The authorization server advertises scopes that grant overly "
                    f"broad access: {', '.join(broad_scopes)}. An attacker who "
                    "obtains a token with these scopes gains excessive privileges."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Use fine-grained scopes following the principle of least privilege.",
                cwe=269,
                tags=["auth", "oauth2", "scope-overgranting"],
            ))

        # 5. No token endpoint auth methods
        if "none" in config.token_endpoint_auth_methods_supported:
            findings.append(Finding(
                title="OAuth2 token endpoint allows unauthenticated clients",
                description=(
                    "The token endpoint auth methods include 'none', meaning "
                    "any client can request tokens without authenticating. "
                    "This is only acceptable for public clients using PKCE."
                ),
                severity=Severity.LOW,
                target=target,
                remediation=(
                    "Require client authentication (client_secret_post, "
                    "client_secret_basic, or private_key_jwt) unless the client "
                    "is a public SPA using PKCE."
                ),
                cwe=287,
                tags=["auth", "oauth2", "client-auth-none"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Authorize endpoint checks
    # ------------------------------------------------------------------

    async def _check_authorize_endpoint(
        self,
        client: HttpClient,
        config: OAuth2Config,
        target: Target,
    ) -> List[Finding]:
        """Probe the authorize endpoint for redirect_uri and state issues."""
        findings: List[Finding] = []
        auth_url = config.authorization_endpoint

        # Test redirect_uri validation — try an attacker-controlled URI
        test_params = {
            "response_type": "code",
            "client_id": "test_audit_client",
            "redirect_uri": "https://evil-attacker.com/callback",
            "state": "csrf_test_state",
        }
        try:
            resp = await client.get(auth_url, params=test_params)

            # If the server redirects to the evil URI, redirect_uri is
            # not validated
            location = resp.headers.get("location", "")
            if "evil-attacker.com" in location:
                findings.append(Finding(
                    title="OAuth2 redirect_uri not validated",
                    description=(
                        "The authorization endpoint accepted a redirect_uri "
                        "pointing to an attacker-controlled domain "
                        "(https://evil-attacker.com/callback). This enables "
                        "authorization code theft."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=f"Location: {location[:200]}",
                    remediation=(
                        "Implement strict redirect_uri validation — exact match "
                        "against pre-registered URIs."
                    ),
                    cwe=601,
                    tags=["auth", "oauth2", "open-redirect"],
                ))

            # Check if the response reflects back without state
            if resp.status_code in (200, 302):
                if "state=" not in location and "state=" not in resp.text:
                    findings.append(Finding(
                        title="OAuth2 authorize endpoint may not enforce state parameter",
                        description=(
                            "The authorization endpoint response does not appear to "
                            "include the state parameter. Without state validation, "
                            "the OAuth flow is vulnerable to CSRF."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        remediation=(
                            "Always include and validate the 'state' parameter in "
                            "authorization requests and callbacks."
                        ),
                        cwe=352,
                        tags=["auth", "oauth2", "missing-state"],
                    ))

        except (httpx.HTTPError, OSError):
            logger.debug("Could not probe authorize endpoint %s", auth_url)

        return findings

    # ------------------------------------------------------------------
    # Token endpoint TLS check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_token_tls(
        config: OAuth2Config, target: Target,
    ) -> List[Finding]:
        """Flag token endpoints not served over HTTPS."""
        if config.token_endpoint.startswith("http://"):
            return [Finding(
                title="OAuth2 token endpoint served over plain HTTP",
                description=(
                    f"The token endpoint ({config.token_endpoint}) uses HTTP "
                    "instead of HTTPS. Tokens and credentials are transmitted "
                    "in the clear."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=config.token_endpoint,
                remediation="Serve the token endpoint exclusively over HTTPS.",
                cwe=319,
                tags=["auth", "oauth2", "no-tls"],
            )]
        return []
