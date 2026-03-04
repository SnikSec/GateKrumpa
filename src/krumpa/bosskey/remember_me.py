"""Remember-me token security analysis — lifetime, revocability, entropy.

Phase 4 item #52.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class RememberMeToken:
    """Captured remember-me token with metadata."""
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    max_age: Optional[int] = None
    expires: Optional[str] = None


@dataclass
class TokenAnalysis:
    """Results of analyzing a remember-me token."""
    entropy_bits: float = 0.0
    is_predictable: bool = False
    has_user_data: bool = False
    encoding: str = "unknown"
    length: int = 0
    charset_size: int = 0
    flags_missing: List[str] = field(default_factory=list)


# Known remember-me cookie names across frameworks
REMEMBER_ME_NAMES = [
    "remember_me", "rememberme", "remember-me",
    "remember_token", "remembertoken",
    "persistent_token", "persistentlogin",
    "stay_logged_in", "stayloggedin",
    "keep_me_logged_in", "keeploggedin",
    "autologin", "auto_login",
    "_session_remember", "remember",
    "persistent", "persistent_session",
    "JSESSIONID_REMEMBER",
    "SPRING_SECURITY_REMEMBER_ME_COOKIE",
    ".ASPXAUTH",
]


class RememberMeAnalyzer:
    """Analyze remember-me token implementations for security issues.

    Checks:
    - Token entropy and predictability
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Token lifetime (excessive expiry)
    - Token revocability (logout invalidation)
    - Presence of user data in token (base64-decoded)
    - Multiple token correlation (sequential predictability)
    """

    # Reasonable max age: 30 days in seconds
    MAX_REASONABLE_AGE = 30 * 24 * 3600
    MIN_ENTROPY_BITS = 128

    def __init__(
        self,
        login_url: Optional[str] = None,
        logout_url: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> None:
        self._login_url = login_url
        self._logout_url = logout_url
        self._credentials = credentials or {}
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all remember-me checks against the target."""
        findings: List[Finding] = []
        url = target.url

        # 1. Discover remember-me cookies
        tokens = await self._discover_tokens(url, target)

        if not tokens:
            return findings

        for token in tokens:
            # 2. Analyze token security
            analysis = self._analyze_token(token)
            findings.extend(self._check_token_flags(token, analysis, target))
            findings.extend(self._check_token_entropy(token, analysis, target))
            findings.extend(self._check_token_lifetime(token, target))
            findings.extend(self._check_user_data_leakage(token, analysis, target))

        # 3. Revocability test
        findings.extend(await self._test_revocability(url, tokens, target))

        # 4. Sequential predictability
        findings.extend(await self._test_sequential_predictability(url, target))

        return findings

    # ----------------------------------------------------------
    # Token discovery
    # ----------------------------------------------------------

    async def _discover_tokens(
        self, url: str, target: Target,
    ) -> List[RememberMeToken]:
        """Discover remember-me tokens from login responses."""
        tokens: List[RememberMeToken] = []
        if not self._client:
            return tokens

        # Try login with remember-me flag
        login_urls = [
            self._login_url,
            f"{url}/login",
            f"{url}/auth/login",
            f"{url}/api/auth/login",
            f"{url}/session",
        ]

        remember_params = [
            {"remember_me": "true"},
            {"remember": "1"},
            {"rememberme": "on"},
            {"stay_logged_in": "true"},
            {"keep_me_logged_in": "true"},
        ]

        for login_url in login_urls:
            if not login_url:
                continue

            for params in remember_params:
                try:
                    body = {**self._credentials, **params}
                    resp = await self._client.request(
                        "POST", login_url,
                        json_body=body,
                    )

                    # Extract Set-Cookie headers
                    new_tokens = self._extract_remember_tokens(resp, url)
                    tokens.extend(new_tokens)

                    if tokens:
                        return tokens  # Found some, stop probing

                except Exception:
                    continue

        return tokens

    def _extract_remember_tokens(self, resp: Any, url: str) -> List[RememberMeToken]:
        """Extract remember-me tokens from response headers."""
        tokens: List[RememberMeToken] = []

        if not hasattr(resp, "headers"):
            return tokens

        # Check all Set-Cookie headers
        cookies_raw: List[str] = []
        headers = resp.headers
        if hasattr(headers, "get_list"):
            cookies_raw = headers.get_list("set-cookie")
        elif hasattr(headers, "getlist"):
            cookies_raw = headers.getlist("set-cookie")
        else:
            cookie_val = headers.get("set-cookie", "")
            if cookie_val:
                cookies_raw = [cookie_val]

        for cookie_str in cookies_raw:
            token = self._parse_cookie(cookie_str, url)
            if token and self._is_remember_me_cookie(token.name):
                tokens.append(token)

        return tokens

    def _parse_cookie(self, cookie_str: str, url: str) -> Optional[RememberMeToken]:
        """Parse a Set-Cookie header into a RememberMeToken."""
        parts = cookie_str.split(";")
        if not parts:
            return None

        name_value = parts[0].strip()
        if "=" not in name_value:
            return None

        name, _, value = name_value.partition("=")
        name = name.strip()
        value = value.strip()

        token = RememberMeToken(name=name, value=value)

        for part in parts[1:]:
            part = part.strip().lower()
            if part == "secure":
                token.secure = True
            elif part == "httponly":
                token.httponly = True
            elif part.startswith("samesite="):
                token.samesite = part.split("=", 1)[1].strip()
            elif part.startswith("max-age="):
                try:
                    token.max_age = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif part.startswith("expires="):
                token.expires = part.split("=", 1)[1].strip()
            elif part.startswith("domain="):
                token.domain = part.split("=", 1)[1].strip()
            elif part.startswith("path="):
                token.path = part.split("=", 1)[1].strip()

        return token

    def _is_remember_me_cookie(self, name: str) -> bool:
        """Check if a cookie name looks like a remember-me token."""
        name_lower = name.lower()
        return any(rm.lower() == name_lower for rm in REMEMBER_ME_NAMES) or any(
            kw in name_lower
            for kw in ["remember", "persistent", "autologin", "keeplogged", "staylogged"]
        )

    # ----------------------------------------------------------
    # Token analysis
    # ----------------------------------------------------------

    def _analyze_token(self, token: RememberMeToken) -> TokenAnalysis:
        """Analyze a token's security properties."""
        analysis = TokenAnalysis()
        value = token.value
        analysis.length = len(value)

        # Detect charset and calculate entropy
        chars_used: Set[str] = set(value)
        analysis.charset_size = len(chars_used)

        if analysis.charset_size > 0 and analysis.length > 0:
            analysis.entropy_bits = math.log2(analysis.charset_size) * analysis.length

        # Check encoding
        if re.match(r"^[A-Za-z0-9+/]+=*$", value) and len(value) % 4 == 0:
            analysis.encoding = "base64"
            # Try decoding to check for user data
            try:
                import base64
                decoded = base64.b64decode(value).decode("utf-8", errors="replace")
                if any(kw in decoded.lower() for kw in ["user", "admin", "email", "@", "id="]):
                    analysis.has_user_data = True
            except Exception:
                pass
        elif re.match(r"^[0-9a-fA-F]+$", value):
            analysis.encoding = "hex"
        elif re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", value):
            analysis.encoding = "jwt"

        # Check predictability
        if analysis.length < 16:
            analysis.is_predictable = True
        elif re.match(r"^\d+$", value):
            analysis.is_predictable = True  # Numeric only — likely sequential

        # Missing flags
        if not token.secure:
            analysis.flags_missing.append("Secure")
        if not token.httponly:
            analysis.flags_missing.append("HttpOnly")
        if not token.samesite or token.samesite.lower() == "none":
            analysis.flags_missing.append("SameSite")

        return analysis

    # ----------------------------------------------------------
    # Security checks
    # ----------------------------------------------------------

    def _check_token_flags(
        self, token: RememberMeToken, analysis: TokenAnalysis, target: Target,
    ) -> List[Finding]:
        """Check cookie security flags."""
        findings: List[Finding] = []

        if not token.secure:
            findings.append(Finding(
                title=f"Remember-me cookie '{token.name}' missing Secure flag",
                description=(
                    f"The remember-me cookie '{token.name}' is not marked Secure, "
                    f"meaning it can be sent over unencrypted HTTP connections. "
                    f"An attacker on the network can intercept the token."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=f"Cookie: {token.name}; flags: Secure=false",
                remediation="Set the Secure flag on all remember-me cookies.",
                cwe=614,
                tags=["remember-me", "cookie-flags", "bosskey"],
            ))

        if not token.httponly:
            findings.append(Finding(
                title=f"Remember-me cookie '{token.name}' missing HttpOnly flag",
                description=(
                    f"The remember-me cookie '{token.name}' is not marked HttpOnly, "
                    f"meaning it can be accessed via JavaScript. An XSS attack "
                    f"can steal the persistent session token."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Cookie: {token.name}; flags: HttpOnly=false",
                remediation="Set the HttpOnly flag on all remember-me cookies.",
                cwe=1004,
                tags=["remember-me", "cookie-flags", "bosskey"],
            ))

        if not token.samesite or token.samesite.lower() == "none":
            findings.append(Finding(
                title=f"Remember-me cookie '{token.name}' missing SameSite protection",
                description=(
                    f"The remember-me cookie '{token.name}' has no SameSite attribute "
                    f"or SameSite=None. This makes it vulnerable to CSRF attacks "
                    f"targeting the persistent session."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Cookie: {token.name}; SameSite={token.samesite or 'not set'}",
                remediation="Set SameSite=Lax or SameSite=Strict on remember-me cookies.",
                cwe=352,
                tags=["remember-me", "cookie-flags", "csrf", "bosskey"],
            ))

        return findings

    def _check_token_entropy(
        self, token: RememberMeToken, analysis: TokenAnalysis, target: Target,
    ) -> List[Finding]:
        """Check token randomness/entropy."""
        findings: List[Finding] = []

        if analysis.entropy_bits < self.MIN_ENTROPY_BITS:
            findings.append(Finding(
                title=f"Remember-me token '{token.name}' has low entropy",
                description=(
                    f"The remember-me token has approximately {analysis.entropy_bits:.0f} bits "
                    f"of entropy (minimum recommended: {self.MIN_ENTROPY_BITS}). "
                    f"Length={analysis.length}, charset_size={analysis.charset_size}. "
                    f"Low entropy tokens may be brute-forced."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence=(
                    f"Token: {token.value[:20]}...\n"
                    f"Entropy: {analysis.entropy_bits:.1f} bits\n"
                    f"Length: {analysis.length}\n"
                    f"Encoding: {analysis.encoding}"
                ),
                remediation=(
                    "Generate remember-me tokens using a CSPRNG with at least "
                    "128 bits of entropy. Use a token length of 32+ hex characters."
                ),
                cwe=330,
                tags=["remember-me", "entropy", "bosskey"],
            ))

        if analysis.is_predictable:
            findings.append(Finding(
                title=f"Remember-me token '{token.name}' appears predictable",
                description=(
                    f"The token value appears to use a predictable pattern "
                    f"(numeric-only, too short, or sequential). "
                    f"Encoding: {analysis.encoding}, length: {analysis.length}."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=f"Token: {token.value[:30]}...",
                remediation="Use cryptographically random tokens, not sequential or time-based values.",
                cwe=340,
                tags=["remember-me", "predictable", "bosskey"],
            ))

        return findings

    def _check_token_lifetime(
        self, token: RememberMeToken, target: Target,
    ) -> List[Finding]:
        """Check if token lifetime is excessively long."""
        findings: List[Finding] = []

        if token.max_age and token.max_age > self.MAX_REASONABLE_AGE:
            days = token.max_age / 86400
            findings.append(Finding(
                title=f"Remember-me token '{token.name}' has excessive lifetime",
                description=(
                    f"The remember-me cookie has a max-age of {days:.0f} days. "
                    f"Long-lived tokens increase the window for token theft. "
                    f"Recommended maximum: 30 days."
                ),
                severity=Severity.LOW,
                target=target,
                evidence=f"Cookie: {token.name}; max-age={token.max_age} ({days:.0f} days)",
                remediation=(
                    "Limit remember-me token lifetime to 30 days or less. "
                    "Implement sliding expiration with re-authentication."
                ),
                cwe=613,
                tags=["remember-me", "lifetime", "bosskey"],
            ))

        return findings

    def _check_user_data_leakage(
        self, token: RememberMeToken, analysis: TokenAnalysis, target: Target,
    ) -> List[Finding]:
        """Check if the token contains user data."""
        findings: List[Finding] = []

        if analysis.has_user_data:
            findings.append(Finding(
                title=f"Remember-me token '{token.name}' contains user data",
                description=(
                    f"The remember-me token appears to contain user-identifiable "
                    f"data when decoded ({analysis.encoding}). Tokens should be "
                    f"opaque references to server-side sessions, not containers "
                    f"of user information."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=f"Encoding: {analysis.encoding}, contains user-identifying patterns",
                remediation=(
                    "Use opaque, random token values that map to server-side "
                    "session records. Do not embed user data in the token."
                ),
                cwe=200,
                tags=["remember-me", "data-leakage", "bosskey"],
            ))

        return findings

    # ----------------------------------------------------------
    # Revocability test
    # ----------------------------------------------------------

    async def _test_revocability(
        self, url: str, tokens: List[RememberMeToken], target: Target,
    ) -> List[Finding]:
        """Test if remember-me tokens are invalidated after logout."""
        findings: List[Finding] = []
        if not self._client or not tokens:
            return findings

        logout_urls = [
            self._logout_url,
            f"{url}/logout",
            f"{url}/auth/logout",
            f"{url}/api/auth/logout",
            f"{url}/session",
        ]

        for token in tokens:
            # First, verify the token works (access an auth-required page)
            cookie_header = f"{token.name}={token.value}"

            try:
                # Access with token
                pre_resp = await self._client.request(
                    "GET", url,
                    headers={"Cookie": cookie_header},
                )
                pre_status = pre_resp.status_code

                # Attempt logout
                for logout_url in logout_urls:
                    if not logout_url:
                        continue
                    try:
                        await self._client.request(
                            "POST", logout_url,
                            headers={"Cookie": cookie_header},
                        )
                        break
                    except Exception:
                        continue

                # Try using the old token again
                post_resp = await self._client.request(
                    "GET", url,
                    headers={"Cookie": cookie_header},
                )

                # If both pre and post return the same authenticated response,
                # the token was not revoked
                if (pre_status in (200, 302) and
                    post_resp.status_code == pre_status and
                    post_resp.status_code not in (401, 403)):

                    post_text = post_resp.text.lower()
                    if "login" not in post_text and "sign in" not in post_text:
                        findings.append(Finding(
                            title=f"Remember-me token '{token.name}' not revoked on logout",
                            description=(
                                f"After logout, the remember-me token is still accepted. "
                                f"An attacker who obtains the token retains access "
                                f"even after the user logs out."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Pre-logout status: {pre_status}\n"
                                f"Post-logout status: {post_resp.status_code}"
                            ),
                            remediation=(
                                "Invalidate remember-me tokens server-side on logout. "
                                "Maintain a revocation list or delete the token record."
                            ),
                            cwe=613,
                            tags=["remember-me", "revocability", "logout", "bosskey"],
                        ))

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Sequential predictability
    # ----------------------------------------------------------

    async def _test_sequential_predictability(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Collect multiple tokens to check for sequential patterns."""
        findings: List[Finding] = []
        if not self._client or not self._credentials:
            return findings

        login_url = self._login_url or f"{url}/login"
        collected_tokens: List[str] = []

        for _ in range(3):
            try:
                body = {**self._credentials, "remember_me": "true"}
                resp = await self._client.request("POST", login_url, json_body=body)
                new_tokens = self._extract_remember_tokens(resp, url)
                for t in new_tokens:
                    collected_tokens.append(t.value)
            except Exception:
                break

        if len(collected_tokens) >= 2:
            # Check for sequential patterns
            if self._tokens_are_sequential(collected_tokens):
                findings.append(Finding(
                    title="Remember-me tokens appear sequential",
                    description=(
                        f"Multiple remember-me tokens show sequential or "
                        f"predictable patterns. Collected {len(collected_tokens)} tokens. "
                        f"An attacker can predict future token values."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=f"Tokens: {', '.join(t[:20] + '...' for t in collected_tokens)}",
                    remediation="Use a CSPRNG for token generation. Avoid sequential or time-based values.",
                    cwe=340,
                    tags=["remember-me", "sequential", "predictable", "bosskey"],
                ))

        return findings

    def _tokens_are_sequential(self, tokens: List[str]) -> bool:
        """Check if tokens show sequential patterns."""
        if len(tokens) < 2:
            return False

        # Try numeric interpretation
        try:
            nums = [int(t) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            # All same diff = sequential
            if len(set(diffs)) == 1:
                return True
        except ValueError:
            pass

        # Try hex interpretation
        try:
            nums = [int(t, 16) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if len(set(diffs)) == 1 and diffs[0] != 0:
                return True
        except ValueError:
            pass

        # Check for common prefix length growing/shrinking — timestamp patterns
        if len(tokens) >= 2:
            common_prefix_len = 0
            t0, t1 = tokens[0], tokens[1]
            for c0, c1 in zip(t0, t1):
                if c0 == c1:
                    common_prefix_len += 1
                else:
                    break

            # If >80% of the token is the same, likely time-based
            if common_prefix_len > len(t0) * 0.8:
                return True

        return False
