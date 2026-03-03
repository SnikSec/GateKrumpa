"""
BossKey — session and token security analyser.

Inspects HTTP responses for session-related weaknesses:
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Session token entropy
  - JWT signature and claims analysis
  - Token expiry / lifetime checks
"""

from __future__ import annotations

import base64
import json
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.bosskey.session")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_COOKIE_PARSE_RE = re.compile(
    r"(?P<name>[^=]+)=(?P<value>[^;]*)"
    r"(?P<attrs>[^,]*)",
    re.IGNORECASE,
)


@dataclass
class CookieInfo:
    """Parsed representation of a single Set-Cookie header."""
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str = ""        # "Strict", "Lax", "None", or ""
    path: str = "/"
    domain: str = ""
    max_age: Optional[int] = None
    raw: str = ""


@dataclass
class JWTInfo:
    """Decoded (but not verified) JWT token."""
    raw: str
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature_present: bool = False
    algorithm: str = ""
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SessionAnalyzer
# ---------------------------------------------------------------------------

class SessionAnalyzer:
    """
    Analyse session tokens and cookies extracted from HTTP responses.

    Parameters
    ----------
    min_entropy_bits:
        Minimum acceptable Shannon entropy (in bits-per-char) for a
        session token value. Tokens below this produce a finding.
    """

    def __init__(self, *, min_entropy_bits: float = 3.5) -> None:
        self.min_entropy_bits = min_entropy_bits

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse_cookies(
        self,
        set_cookie_headers: List[str],
        target: Target,
        *,
        is_https: bool = True,
    ) -> List[Finding]:
        """
        Parse ``Set-Cookie`` headers and return findings for any weaknesses.
        """
        findings: List[Finding] = []
        cookies = [self.parse_cookie(h) for h in set_cookie_headers]

        for cookie in cookies:
            findings.extend(self._check_cookie_flags(cookie, target, is_https))
            findings.extend(self._check_entropy(cookie, target))

        return findings

    def analyse_tokens(
        self,
        raw_values: List[str],
        target: Target,
    ) -> List[Finding]:
        """
        Look for JWT tokens in arbitrary header / body values and analyse
        them for common weaknesses.
        """
        findings: List[Finding] = []
        seen: Set[str] = set()

        for value in raw_values:
            for match in _JWT_RE.finditer(value):
                token = match.group(0)
                if token in seen:
                    continue
                seen.add(token)
                jwt = self.decode_jwt(token)
                findings.extend(self._check_jwt(jwt, target))

        return findings

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_cookie(header: str) -> CookieInfo:
        """Parse a single ``Set-Cookie`` header string."""
        parts = header.split(";")
        name_value = parts[0].strip()
        eq = name_value.find("=")
        if eq == -1:
            name, value = name_value, ""
        else:
            name, value = name_value[:eq].strip(), name_value[eq + 1:].strip()

        cookie = CookieInfo(name=name, value=value, raw=header)

        for attr in parts[1:]:
            attr = attr.strip().lower()
            if attr == "secure":
                cookie.secure = True
            elif attr == "httponly":
                cookie.httponly = True
            elif attr.startswith("samesite="):
                cookie.samesite = attr.split("=", 1)[1].strip().capitalize()
            elif attr.startswith("path="):
                cookie.path = attr.split("=", 1)[1].strip()
            elif attr.startswith("domain="):
                cookie.domain = attr.split("=", 1)[1].strip()
            elif attr.startswith("max-age="):
                try:
                    cookie.max_age = int(attr.split("=", 1)[1].strip())
                except ValueError:
                    pass

        return cookie

    @staticmethod
    def decode_jwt(token: str) -> JWTInfo:
        """Decode a JWT without verifying the signature."""
        info = JWTInfo(raw=token)
        parts = token.split(".")
        if len(parts) < 2:
            info.errors.append("Not a valid JWT — fewer than 2 segments")
            return info

        # Header
        try:
            header_b = base64.urlsafe_b64decode(parts[0] + "==")
            info.header = json.loads(header_b)
            info.algorithm = info.header.get("alg", "")
        except Exception as exc:
            info.errors.append(f"Failed to decode header: {exc}")

        # Payload
        try:
            payload_b = base64.urlsafe_b64decode(parts[1] + "==")
            info.payload = json.loads(payload_b)
        except Exception as exc:
            info.errors.append(f"Failed to decode payload: {exc}")

        info.signature_present = len(parts) >= 3 and bool(parts[2])
        return info

    @staticmethod
    def shannon_entropy(value: str) -> float:
        """Return Shannon entropy in bits-per-character."""
        if not value:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_cookie_flags(
        self, cookie: CookieInfo, target: Target, is_https: bool,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if is_https and not cookie.secure:
            findings.append(Finding(
                title=f"Cookie '{cookie.name}' missing Secure flag",
                description=(
                    f"The cookie '{cookie.name}' is set over HTTPS but lacks the Secure "
                    "attribute, allowing it to be transmitted over plain HTTP."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Add the Secure flag to all session cookies served over HTTPS.",
                cwe=614,
                tags=["auth", "cookie", "secure-flag"],
            ))

        if not cookie.httponly:
            findings.append(Finding(
                title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                description=(
                    f"The cookie '{cookie.name}' lacks the HttpOnly attribute, making it "
                    "accessible to client-side JavaScript (XSS risk)."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Add the HttpOnly flag to session cookies.",
                cwe=1004,
                tags=["auth", "cookie", "httponly"],
            ))

        if not cookie.samesite or cookie.samesite == "None":
            findings.append(Finding(
                title=f"Cookie '{cookie.name}' has weak SameSite policy",
                description=(
                    f"The cookie '{cookie.name}' has SameSite={cookie.samesite or '(absent)'}, "
                    "providing limited CSRF protection."
                ),
                severity=Severity.LOW,
                target=target,
                remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                cwe=352,
                tags=["auth", "cookie", "samesite"],
            ))

        return findings

    def _check_entropy(
        self, cookie: CookieInfo, target: Target,
    ) -> List[Finding]:
        entropy = self.shannon_entropy(cookie.value)
        if len(cookie.value) >= 8 and entropy < self.min_entropy_bits:
            return [Finding(
                title=f"Cookie '{cookie.name}' has low entropy ({entropy:.2f} bits/char)",
                description=(
                    f"The session token '{cookie.name}' has a Shannon entropy of "
                    f"{entropy:.2f} bits/char (minimum: {self.min_entropy_bits}). "
                    "This may indicate a predictable session identifier."
                ),
                severity=Severity.HIGH,
                target=target,
                remediation="Use a cryptographically secure random generator for session tokens.",
                cwe=330,
                tags=["auth", "session", "entropy"],
            )]
        return []

    def _check_jwt(self, jwt: JWTInfo, target: Target) -> List[Finding]:
        findings: List[Finding] = []

        # Warn that signature was NOT verified (analysis-only decode)
        if jwt.algorithm and jwt.algorithm.lower() != "none" and jwt.signature_present:
            findings.append(Finding(
                title="JWT signature not verified (analysis-only decode)",
                description=(
                    f"A JWT with alg={jwt.algorithm} was decoded for inspection but its "
                    "signature was not cryptographically verified.  The claims shown in "
                    "other findings for this token are unverified."
                ),
                severity=Severity.INFO,
                target=target,
                tags=["auth", "jwt", "sig-not-verified"],
            ))

        if jwt.algorithm.lower() == "none":
            findings.append(Finding(
                title="JWT uses 'none' algorithm",
                description=(
                    "A JWT token was found with alg=none, meaning it has no cryptographic "
                    "signature. An attacker can forge arbitrary tokens."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence=jwt.raw[:80] + "..." if len(jwt.raw) > 80 else jwt.raw,
                remediation="Reject JWTs with alg=none; enforce a strong signing algorithm (e.g. RS256).",
                cwe=345,
                tags=["auth", "jwt", "alg-none"],
            ))

        if jwt.algorithm.lower().startswith("hs") and not jwt.signature_present:
            findings.append(Finding(
                title="JWT signed with HMAC but signature is empty",
                description="A JWT declares an HMAC algorithm but the signature segment is empty.",
                severity=Severity.HIGH,
                target=target,
                remediation="Ensure all JWTs carry a valid signature.",
                cwe=345,
                tags=["auth", "jwt", "missing-sig"],
            ))

        # Check for missing expiry
        if jwt.payload and "exp" not in jwt.payload:
            findings.append(Finding(
                title="JWT missing expiration claim (exp)",
                description=(
                    "The JWT payload does not contain an 'exp' claim. Tokens without "
                    "expiry are valid indefinitely if leaked."
                ),
                severity=Severity.MEDIUM,
                target=target,
                remediation="Always include an 'exp' claim with a reasonable lifetime.",
                cwe=613,
                tags=["auth", "jwt", "no-expiry"],
            ))

        return findings
