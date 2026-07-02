"""
BossKey — Cloud-hosted identity and OAuth2 provider surface analysis (Epic 5).

Extends the existing OAuth2/OIDC coverage with cloud-specific identity
providers:
  - AWS Cognito user pools and hosted UI
  - Azure Entra ID / Microsoft identity platform tenant flows
  - Google Identity Platform / IAP
  - Generic PKCE enforcement and callback URI drift

Activated when ``FingerprintResult`` contains cloud identity signals or an
OAuth2 flow is detected in the scan context.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, List
from urllib.parse import urljoin, urlparse

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.cloud_identity")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OIDC_WELL_KNOWN = "/.well-known/openid-configuration"

# Cognito hosted UI patterns
_COGNITO_DOMAINS = re.compile(r"cognito|auth\.ap-|auth\.eu-|auth\.us-|\.auth\.[a-z0-9-]+\.amazoncognito\.com", re.IGNORECASE)

# Entra / AAD patterns
_ENTRA_PATTERNS = re.compile(r"login\.microsoftonline\.com|microsoftonline|azure-ad|aad", re.IGNORECASE)

# Google IAP patterns
_GOOGLE_IAP_PATTERNS = re.compile(r"iap\.googleapis\.com|x-goog-authenticated-user", re.IGNORECASE)


class CloudIdentityAnalyzer(HttpClientMixin):
    """Detect and test cloud-hosted identity surface exposures."""

    def __init__(self, *, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=15.0, retries=1)

        # Determine which identity provider to probe based on fingerprint signals
        fp_result = ctx.metadata.get("fingerprints", {}).get(target.url)
        techs = set(getattr(fp_result, "technologies", [])) if fp_result else set()
        redirect_chain = list(getattr(fp_result, "redirect_chain", [])) if fp_result else []
        all_urls = [target.url] + redirect_chain

        is_cognito = any(_COGNITO_DOMAINS.search(u) for u in all_urls)
        is_entra = any(_ENTRA_PATTERNS.search(u) for u in all_urls)
        is_gcp_iap = any(_GOOGLE_IAP_PATTERNS.search(u) for u in all_urls)

        try:
            # Generic OIDC metadata probe
            findings.extend(await self._probe_oidc_metadata(client, target, ctx))

            if is_cognito:
                findings.extend(await self._probe_cognito(client, target, ctx))

            if is_entra:
                findings.extend(await self._probe_entra(client, target, ctx))

            if is_gcp_iap:
                findings.extend(await self._probe_gcp_iap(client, target, fp_result))

            # PKCE enforcement check (applies to all OAuth2 providers)
            findings.extend(await self._check_pkce_enforcement(client, target, ctx))

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Generic OIDC
    # ------------------------------------------------------------------

    async def _probe_oidc_metadata(
        self, client: HttpClient, target: Target, ctx: ScanContext
    ) -> List[Finding]:
        findings: List[Finding] = []
        url = f"{target.url.rstrip('/')}{_OIDC_WELL_KNOWN}"
        try:
            resp = await client.get(url)
            if getattr(resp, "status_code", 404) == 200:
                text = getattr(resp, "text", "") or ""
                try:
                    meta = json.loads(text)
                except json.JSONDecodeError:
                    return findings

                # Check for broad scopes in scopes_supported
                scopes = meta.get("scopes_supported", [])
                dangerous_scopes = [s for s in scopes if s in ("profile", "email", "openid", "offline_access")]
                if dangerous_scopes:
                    ctx.metadata.setdefault("oidc_metadata", {})[target.url] = meta

                # Check token endpoint auth methods — if none/client_secret_basic only
                token_auth = meta.get("token_endpoint_auth_methods_supported", [])
                if "none" in token_auth:
                    findings.append(Finding(
                        title="OIDC provider allows public client (no client secret)",
                        description=(
                            f"The OIDC provider at {target.url!r} supports "
                            "token_endpoint_auth_method=none, allowing public clients "
                            "to exchange auth codes without a client secret. "
                            "Without PKCE, authorization codes can be intercepted and replayed."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"token_endpoint_auth_methods_supported: {token_auth}",
                        remediation="Require PKCE (S256) for all public clients. Disable the 'none' auth method.",
                        cwe=345,
                        tags=["auth", "oidc", "oauth2", "public-client"],
                    ))

                # Check response_types — implicit flow (token) is insecure
                response_types = meta.get("response_types_supported", [])
                if "token" in response_types:
                    findings.append(Finding(
                        title="OIDC provider supports implicit flow (response_type=token)",
                        description=(
                            f"The OIDC provider at {target.url!r} supports the OAuth2 implicit "
                            "flow (response_type=token). The implicit flow is deprecated in "
                            "OAuth 2.1 as access tokens in URL fragments are vulnerable to "
                            "referrer header leakage and browser history exposure."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"response_types_supported: {response_types}",
                        remediation="Disable the implicit flow. Use authorization code + PKCE instead.",
                        cwe=345,
                        tags=["auth", "oidc", "oauth2", "implicit-flow"],
                    ))

        except Exception as exc:
            logger.debug("OIDC metadata probe failed for %s: %s", url, exc)
        return findings

    # ------------------------------------------------------------------
    # AWS Cognito
    # ------------------------------------------------------------------

    async def _probe_cognito(
        self, client: HttpClient, target: Target, ctx: ScanContext
    ) -> List[Finding]:
        findings: List[Finding] = []
        base = target.url.rstrip("/")

        # Cognito username enumeration via password reset endpoint
        try:
            reset_url = f"{base}/forgotPassword"
            body = json.dumps({"username": "nonexistent_test_user_krumpa_canary"})
            resp = await client.request(
                "POST", reset_url,
                headers={"Content-Type": "application/json"},
                content=body,
            )
            text = getattr(resp, "text", "") or ""
            status = getattr(resp, "status_code", 0)

            # Cognito verbose error messages reveal user existence
            if "UserNotFoundException" not in text and status == 200:
                pass  # Ambiguous — don't flag
            elif "UserNotFoundException" in text:
                # Different error for existing vs non-existing users = enumeration
                findings.append(Finding(
                    title="Cognito user enumeration via password reset",
                    description=(
                        "The Cognito password reset endpoint returns a verbose "
                        "'UserNotFoundException' error for non-existent users, allowing "
                        "an attacker to enumerate valid usernames."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"POST {reset_url} → {text[:200]}",
                    remediation=(
                        "Configure Cognito to use a generic response for all password "
                        "reset attempts regardless of whether the user exists. "
                        "Enable 'Prevent user existence errors' in the Cognito user pool."
                    ),
                    cwe=204,
                    tags=["auth", "cognito", "aws", "user-enumeration"],
                ))
        except Exception as exc:
            logger.debug("Cognito password reset probe failed: %s", exc)

        # Check for unauthenticated identity pool access
        try:
            oidc_url = f"{base}{_OIDC_WELL_KNOWN}"
            resp = await client.get(oidc_url)
            if getattr(resp, "status_code", 404) == 200:
                meta = json.loads(getattr(resp, "text", "{}") or "{}")
                issuer = meta.get("issuer", "")
                if "cognito-idp" in issuer:
                    # Check logout_uri for open redirect
                    logout_ep = meta.get("end_session_endpoint", "")
                    if logout_ep:
                        logout_redirect = f"{logout_ep}?logout_uri=https://evil.example.com"
                        try:
                            redir_resp = await client.request("GET", logout_redirect)
                            location = ""
                            headers = getattr(redir_resp, "headers", {}) or {}
                            for k, v in headers.items():
                                if k.lower() == "location":
                                    location = v
                                    break
                            if "evil.example.com" in location:
                                findings.append(Finding(
                                    title="Cognito logout endpoint open redirect",
                                    description=(
                                        f"The Cognito logout endpoint at {logout_ep!r} "
                                        "redirects to an attacker-controlled URL without "
                                        "validating the logout_uri parameter."
                                    ),
                                    severity=Severity.HIGH,
                                    target=target,
                                    evidence=f"Logout URL: {logout_redirect}\nRedirect location: {location}",
                                    remediation=(
                                        "Register allowed logout URIs in the Cognito app client "
                                        "settings and validate that logout_uri matches an allowed URL."
                                    ),
                                    cwe=601,
                                    tags=["auth", "cognito", "aws", "open-redirect"],
                                ))
                        except Exception:
                            pass
        except Exception as exc:
            logger.debug("Cognito OIDC metadata probe failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Azure Entra ID
    # ------------------------------------------------------------------

    async def _probe_entra(
        self, client: HttpClient, target: Target, ctx: ScanContext
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Detect tenant from redirect chain
        oidc_meta = ctx.metadata.get("oidc_metadata", {}).get(target.url, {})
        issuer = oidc_meta.get("issuer", "")
        token_ep = oidc_meta.get("token_endpoint", "")

        # Check for audience restriction in token endpoint hints
        if "microsoftonline.com" in issuer or "microsoftonline.com" in token_ep:
            # Check for multi-tenant app misconfiguration (issuer = common or organizations)
            if "/common/" in issuer or "/organizations/" in issuer:
                findings.append(Finding(
                    title="Entra ID app configured for multi-tenant access",
                    description=(
                        "The application uses a multi-tenant Entra ID issuer "
                        f"({issuer!r}). Multi-tenant apps must explicitly validate "
                        "the 'tid' (tenant) claim in received tokens to prevent "
                        "tokens from other tenants being accepted."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Issuer: {issuer}",
                    remediation=(
                        "Validate the 'tid' claim against a known-good tenant ID on "
                        "every token received. Switch to a single-tenant issuer "
                        "(/{tenant-id}/) if multi-tenant access is not required."
                    ),
                    cwe=346,
                    tags=["auth", "entra", "azure", "multi-tenant", "token-validation"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Google IAP
    # ------------------------------------------------------------------

    async def _probe_gcp_iap(
        self, client: HttpClient, target: Target, fp_result: Any
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Check if IAP headers are present but JWT is not being validated
        raw_headers = getattr(fp_result, "raw_headers", {}) if fp_result else {}
        iap_jwt = raw_headers.get("x-goog-authenticated-user-jwt", "")

        if iap_jwt:
            # Header is present — check if the app is relying on it without backend validation
            findings.append(Finding(
                title="Google IAP JWT header detected — ensure backend validates it",
                description=(
                    "The application returns an X-Goog-Authenticated-User-JWT header, "
                    "indicating it sits behind Google IAP. If the application does not "
                    "independently validate this JWT (audience, signature, expiry), "
                    "direct access to the backend URL bypasses IAP entirely."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Header present: x-goog-authenticated-user-jwt (value redacted)",
                remediation=(
                    "Validate the IAP JWT in every request handler using the Google "
                    "Cloud IAP verification library. Ensure the backend is not "
                    "reachable directly without going through IAP."
                ),
                cwe=287,
                tags=["auth", "gcp", "iap", "jwt-validation"],
            ))

        return findings

    # ------------------------------------------------------------------
    # PKCE enforcement
    # ------------------------------------------------------------------

    async def _check_pkce_enforcement(
        self, client: HttpClient, target: Target, ctx: ScanContext
    ) -> List[Finding]:
        findings: List[Finding] = []
        oidc_meta = ctx.metadata.get("oidc_metadata", {}).get(target.url, {})
        auth_endpoint = oidc_meta.get("authorization_endpoint", "")
        token_endpoint = oidc_meta.get("token_endpoint", "")

        if not (auth_endpoint and token_endpoint):
            return findings

        # Test: attempt token exchange without code_verifier (should fail if PKCE enforced)
        try:
            # Step 1: Start an auth code flow without code_challenge
            import secrets
            state = secrets.token_hex(16)
            auth_req = (
                f"{auth_endpoint}?response_type=code&client_id=test_client"
                f"&redirect_uri=https%3A%2F%2Fkrumpa-canary.invalid%2Fcallback"
                f"&scope=openid&state={state}"
            )
            auth_resp = await client.request("GET", auth_req)
            # We can't complete the flow without a real code, but we can check if
            # code_challenge_method is required in the error response
            text = getattr(auth_resp, "text", "") or ""
            if "code_challenge" not in text.lower() and "pkce" not in text.lower():
                # Authorization endpoint accepted the request without requiring PKCE
                if getattr(auth_resp, "status_code", 0) in (200, 302):
                    findings.append(Finding(
                        title="OAuth2 authorization server may not enforce PKCE",
                        description=(
                            "The authorization endpoint accepted a request without "
                            "a code_challenge parameter. If PKCE is not enforced, "
                            "authorization codes can be exchanged by any client, "
                            "enabling authorization code interception attacks."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Auth endpoint: {auth_endpoint}\nNo code_challenge required in response",
                        remediation="Configure the authorization server to require code_challenge (S256) for all public clients.",
                        cwe=345,
                        tags=["auth", "oauth2", "pkce", "authorization-code"],
                    ))
        except Exception as exc:
            logger.debug("PKCE enforcement check failed: %s", exc)

        return findings
