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
