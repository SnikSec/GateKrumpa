"""
BossKey — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from krumpa.core import BaseModule, Finding, ScanContext, Target
from krumpa.bosskey.session_analyzer import SessionAnalyzer
from krumpa.bosskey.auth_probe import AuthEndpoint, AuthProbe
from krumpa.bosskey.csrf_checker import CsrfChecker
from krumpa.bosskey.oauth2_analyzer import OAuth2Analyzer
from krumpa.bosskey.session_fixation import SessionFixationChecker
from krumpa.bosskey.password_policy import PasswordPolicyTester
from krumpa.bosskey.session_timeout import SessionTimeoutTester
from krumpa.bosskey.lockout_tester import AccountLockoutTester
from krumpa.bosskey.jwt_attacks import JwtAdvancedTester
from krumpa.bosskey.rbac_matrix import RbacMatrixBuilder
from krumpa.bosskey.auth_scheme_enforcer import AuthSchemeEnforcer
from krumpa.bosskey.password_reset_tester import PasswordResetTester
from krumpa.bosskey.credential_transport import CredentialTransportAuditor
from krumpa.bosskey.token_storage import TokenStorageAnalyzer
from krumpa.bosskey.registration_tester import RegistrationTester
from krumpa.bosskey.mfa_tester import MfaTester
from krumpa.bosskey.saml_analyzer import SamlAnalyzer
from krumpa.bosskey.remember_me import RememberMeAnalyzer
from krumpa.bosskey.concurrent_sessions import ConcurrentSessionTester

logger = logging.getLogger("krumpa.bosskey")


class BossKeyModule(BaseModule):
    """Authentication modelling and session analysis."""

    name = "BossKey"
    description = "Auth Modeling — session analysis, credential testing, authz probing"
    dependencies: List[str] = ["SneakyGits"]  # needs discovered targets + cookies

    def __init__(
        self,
        *,
        min_entropy_bits: float = 3.5,
        login_endpoints: Optional[List[AuthEndpoint]] = None,
        rate_limit_threshold: int = 5,
    ) -> None:
        super().__init__()
        self._session_analyzer = SessionAnalyzer(min_entropy_bits=min_entropy_bits)
        self._auth_probe = AuthProbe(rate_limit_threshold=rate_limit_threshold)
        self._csrf_checker = CsrfChecker()
        self._oauth2_analyzer = OAuth2Analyzer()
        self._session_fixation = SessionFixationChecker()
        self._password_policy = PasswordPolicyTester()
        self._session_timeout = SessionTimeoutTester()
        self._lockout_tester = AccountLockoutTester()
        self._jwt_tester = JwtAdvancedTester()
        self._rbac_builder = RbacMatrixBuilder()
        self._auth_scheme_enforcer = AuthSchemeEnforcer()
        self._password_reset = PasswordResetTester()
        self._credential_transport = CredentialTransportAuditor()
        self._token_storage = TokenStorageAnalyzer()
        self._registration_tester = RegistrationTester()
        self._mfa_tester = MfaTester()
        self._saml_analyzer = SamlAnalyzer()
        self._remember_me = RememberMeAnalyzer()
        self._concurrent_sessions = ConcurrentSessionTester()
        self._login_endpoints = login_endpoints or []

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client into sub-components."""
        if ctx.http_client:
            self._auth_probe._client = ctx.http_client
            self._auth_probe._owns_client = False
            self._csrf_checker._client = ctx.http_client
            self._csrf_checker._owns_client = False
            self._oauth2_analyzer._client = ctx.http_client
            self._oauth2_analyzer._owns_client = False
            self._session_fixation._client = ctx.http_client
            self._session_fixation._owns_client = False
            self._password_policy._client = ctx.http_client
            self._password_policy._owns_client = False
            self._session_timeout._client = ctx.http_client
            self._session_timeout._owns_client = False
            self._lockout_tester._client = ctx.http_client
            self._lockout_tester._owns_client = False
            self._rbac_builder._client = ctx.http_client
            self._rbac_builder._owns_client = False
            self._auth_scheme_enforcer._client = ctx.http_client
            self._auth_scheme_enforcer._owns_client = False
            self._password_reset._client = ctx.http_client
            self._password_reset._owns_client = False
            self._credential_transport._client = ctx.http_client
            self._credential_transport._owns_client = False
            self._token_storage._client = ctx.http_client
            self._token_storage._owns_client = False
            self._registration_tester._client = ctx.http_client
            self._registration_tester._owns_client = False
            self._mfa_tester._client = ctx.http_client
            self._mfa_tester._owns_client = False
            self._saml_analyzer._client = ctx.http_client
            self._saml_analyzer._owns_client = False
            self._remember_me._client = ctx.http_client
            self._remember_me._owns_client = False
            self._concurrent_sessions._client = ctx.http_client
            self._concurrent_sessions._owns_client = False

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # --- Session / cookie analysis on every target --------------------
        for target in ctx.targets:
            logger.info("Analysing session tokens for %s", target.url)
            cookie_findings = await self._analyse_target_session(target, ctx)
            findings.extend(cookie_findings)

        # --- Auth endpoint probing ----------------------------------------
        for ep in self._login_endpoints:
            target = self._find_target(ep.url, ctx) or Target(url=ep.url)
            logger.info("Probing auth endpoint %s", ep.url)
            probe_findings = await self._auth_probe.probe(ep, target)
            findings.extend(probe_findings)

        # --- Also try auto-detected login endpoints from context ----------
        auto_endpoints = self._detect_login_endpoints(ctx)
        for ep in auto_endpoints:
            target = self._find_target(ep.url, ctx) or Target(url=ep.url)
            logger.info("Probing auto-detected auth endpoint %s", ep.url)
            probe_findings = await self._auth_probe.probe(ep, target)
            findings.extend(probe_findings)

        # --- CSRF checks on state-changing targets -------------------------
        for target in ctx.targets:
            if target.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                logger.info("Checking CSRF protection for %s", target.url)
                csrf_findings = await self._csrf_checker.check(target)
                findings.extend(csrf_findings)

        # --- OAuth2 analysis -----------------------------------------------
        if ctx.targets:
            logger.info("Analysing OAuth2 configuration")
            oauth2_findings = await self._oauth2_analyzer.analyze(ctx.targets[0])
            findings.extend(oauth2_findings)

        # --- Session fixation checks on login-like targets -----------------
        login_urls = self._get_login_targets(ctx)
        for target in login_urls:
            logger.info("Testing session fixation on %s", target.url)
            fix_findings = await self._session_fixation.check(target)
            findings.extend(fix_findings)

        # --- Password policy testing on registration/password endpoints ----
        pw_urls = self._get_password_targets(ctx)
        for target in pw_urls:
            logger.info("Testing password policy on %s", target.url)
            pw_findings = await self._password_policy.test(target)
            findings.extend(pw_findings)

        # --- Session timeout testing on login targets ----------------------
        for target in login_urls:
            logger.info("Testing session timeout on %s", target.url)
            timeout_findings = await self._session_timeout.test(target)
            findings.extend(timeout_findings)

        # --- Account lockout testing on login targets ----------------------
        for target in login_urls:
            logger.info("Testing account lockout on %s", target.url)
            lockout_findings = await self._lockout_tester.test(target)
            findings.extend(lockout_findings)

        # --- JWT attack testing on targets with auth tokens ----------------
        for target in ctx.targets:
            auth_header = target.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1]
                jwt_findings = self._jwt_tester.analyze_token(token)
                findings.extend(jwt_findings)

        # --- RBAC matrix building ------------------------------------------
        if ctx.targets:
            rbac_findings = await self._rbac_builder.test_and_report(ctx.targets)
            findings.extend(rbac_findings)

        # --- Auth scheme enforcement on all targets -------------------------
        for target in ctx.targets:
            logger.info("Testing auth scheme enforcement on %s", target.url)
            auth_headers = {k: v for k, v in target.headers.items() if k.lower() == "authorization"}
            scheme_findings = await self._auth_scheme_enforcer.check(
                target, auth_headers=auth_headers or None,
            )
            findings.extend(scheme_findings)

        # --- Password reset flow testing on reset endpoints -----------------
        reset_targets = self._get_reset_targets(ctx)
        for target in reset_targets:
            logger.info("Testing password reset flow on %s", target.url)
            reset_findings = await self._password_reset.test(target)
            findings.extend(reset_findings)

        # --- Credential transport audit on login targets --------------------
        for target in login_urls:
            logger.info("Auditing credential transport on %s", target.url)
            transport_findings = await self._credential_transport.audit(target)
            findings.extend(transport_findings)

        # --- Token storage analysis on all targets --------------------------
        for target in ctx.targets:
            logger.info("Analysing token storage on %s", target.url)
            storage_findings = await self._token_storage.analyze(target)
            findings.extend(storage_findings)

        # --- Registration flow testing on register endpoints ----------------
        reg_targets = self._get_registration_targets(ctx)
        for target in reg_targets:
            logger.info("Testing registration flow on %s", target.url)
            reg_findings = await self._registration_tester.test(target)
            findings.extend(reg_findings)

        # --- MFA testing on MFA/2FA endpoints --------------------------------
        mfa_targets = self._get_mfa_targets(ctx)
        for target in mfa_targets:
            logger.info("Testing MFA on %s", target.url)
            mfa_findings = await self._mfa_tester.test(target)
            findings.extend(mfa_findings)

        # --- SAML analysis on SAML endpoints --------------------------------
        for target in ctx.targets:
            if any(h in target.url.lower() for h in ("/saml", "/sso", "/sls", "/acs")):
                logger.info("Analysing SAML on %s", target.url)
                saml_findings = await self._saml_analyzer.analyze(target)
                findings.extend(saml_findings)

        # --- Remember-me token analysis ------------------------------------
        for target in login_urls:
            logger.info("Analysing remember-me tokens on %s", target.url)
            remember_findings = await self._remember_me.analyze(target)
            findings.extend(remember_findings)

        # --- Concurrent session testing ------------------------------------
        for target in login_urls:
            logger.info("Testing concurrent sessions on %s", target.url)
            concurrent_findings = await self._concurrent_sessions.analyze(target)
            findings.extend(concurrent_findings)

        for f in findings:
            self.add_finding(f)

        logger.info("BossKey complete — %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Session analysis
    # ------------------------------------------------------------------

    async def _analyse_target_session(
        self, target: Target, ctx: ScanContext,
    ) -> List[Finding]:
        """Inspect auth_tokens and any cookie headers stored on the target."""
        findings: List[Finding] = []
        is_https = target.url.startswith("https://")

        # Cookies stored as target metadata (set during recon)
        set_cookies: List[str] = target.metadata.get("set_cookie_headers", [])
        if set_cookies:
            findings.extend(
                self._session_analyzer.analyse_cookies(set_cookies, target, is_https=is_https)
            )

        # JWT / bearer tokens from the scan context
        token_values = list(ctx.auth_tokens.values())
        # Also check Authorization headers on the target
        auth_header = target.headers.get("Authorization", "")
        if auth_header:
            token_values.append(auth_header)

        if token_values:
            findings.extend(self._session_analyzer.analyse_tokens(token_values, target))

        return findings

    # ------------------------------------------------------------------
    # Auto-detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_login_endpoints(ctx: ScanContext) -> List[AuthEndpoint]:
        """
        Heuristic: look for targets whose URL path hints at a login endpoint.
        """
        hints = ("/login", "/signin", "/auth", "/token", "/oauth", "/api/login", "/api/auth")
        endpoints: List[AuthEndpoint] = []
        seen_urls = set()

        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen_urls:
                    seen_urls.add(t.url)
                    endpoints.append(AuthEndpoint(url=t.url))

        return endpoints

    @staticmethod
    def _find_target(url: str, ctx: ScanContext) -> Optional[Target]:
        for t in ctx.targets:
            if t.url == url:
                return t
        return None

    @staticmethod
    def _get_login_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that look like login endpoints."""
        hints = ("/login", "/signin", "/auth", "/token", "/api/login", "/api/auth")
        results: List[Target] = []
        seen: set = set()
        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen:
                    seen.add(t.url)
                    results.append(t)
        return results

    @staticmethod
    def _get_password_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that look like registration or password-change endpoints."""
        hints = ("/register", "/signup", "/password", "/change-password", "/reset-password",
                 "/api/register", "/api/users", "/api/signup")
        results: List[Target] = []
        seen: set = set()
        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen:
                    seen.add(t.url)
                    results.append(t)
        return results

    @staticmethod
    def _get_reset_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that look like password reset endpoints."""
        hints = ("/reset", "/forgot", "/recover", "/password-reset", "/reset-password",
                 "/api/reset", "/api/forgot-password")
        results: List[Target] = []
        seen: set = set()
        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen:
                    seen.add(t.url)
                    results.append(t)
        return results

    @staticmethod
    def _get_registration_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that look like registration endpoints."""
        hints = ("/register", "/signup", "/api/register", "/api/signup",
                 "/create-account", "/api/users")
        results: List[Target] = []
        seen: set = set()
        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen:
                    seen.add(t.url)
                    results.append(t)
        return results

    @staticmethod
    def _get_mfa_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that look like MFA/2FA endpoints."""
        hints = ("/mfa", "/2fa", "/two-factor", "/otp", "/totp", "/verify",
                 "/challenge", "/api/mfa", "/api/2fa")
        results: List[Target] = []
        seen: set = set()
        for t in ctx.targets:
            lower = t.url.lower()
            if any(lower.endswith(h) or h + "?" in lower or h + "/" in lower for h in hints):
                if t.url not in seen:
                    seen.add(t.url)
                    results.append(t)
        return results
