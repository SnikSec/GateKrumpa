"""
RedTeef — OOB (Out-of-Band) verification infrastructure.

Manages a lightweight collaborator server for DNS/HTTP callback verification.
Provides an API to register tokens, check interactions, and correlate
OOB callbacks with injected payloads.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("krumpa.redteef.oob_verifier")


@dataclass
class OobToken:
    """A registered OOB callback token."""
    token: str
    vuln_type: str
    target_url: str
    field_name: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0  # 0 = no expiry
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OobCallback:
    """A received OOB callback."""
    token: str
    callback_type: str  # "dns", "http", "smtp"
    source_ip: str = ""
    received_at: float = 0.0
    request_path: str = ""
    raw_data: str = ""


@dataclass
class OobVerification:
    """The result of verifying an OOB interaction."""
    token: OobToken
    callback: OobCallback
    confirmed: bool
    latency_ms: float = 0.0


class OobVerifier:
    """
    In-memory OOB verification store.

    This class manages the correlation between injected payloads
    (identified by tokens) and received callbacks. In production,
    this would typically integrate with an external DNS/HTTP
    collaborator server.
    """

    def __init__(
        self,
        *,
        domain: str = "oob.example.internal",
        default_ttl: float = 300.0,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        self._domain = domain
        self._default_ttl = ttl_seconds if ttl_seconds is not None else default_ttl
        self._tokens: Dict[str, OobToken] = {}
        self._callbacks: Dict[str, List[OobCallback]] = {}  # token -> callbacks

    @property
    def domain(self) -> str:
        return self._domain

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def register_token(
        self,
        *,
        vuln_type: str,
        target_url: str = "",
        field_name: str = "",
        ttl: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OobToken:
        """Create and register a new OOB token."""
        raw = f"{vuln_type}-{target_url}-{field_name}-{time.monotonic()}"
        token_str = hashlib.sha256(raw.encode()).hexdigest()[:20]

        now = time.monotonic()
        token = OobToken(
            token=token_str,
            vuln_type=vuln_type,
            target_url=target_url,
            field_name=field_name,
            created_at=now,
            expires_at=now + (ttl or self._default_ttl),
            metadata=metadata or {},
        )

        self._tokens[token_str] = token
        return token

    def get_callback_url(self, token: OobToken) -> str:
        """Generate the callback URL for a token."""
        return f"http://{token.token}.{self._domain}/"

    def get_dns_hostname(self, token: OobToken) -> str:
        """Generate the DNS hostname for a token."""
        return f"{token.token}.{self._domain}"

    # ------------------------------------------------------------------
    # Callback recording
    # ------------------------------------------------------------------

    def record_callback(
        self,
        token_str: str,
        callback_type: str,
        *,
        source_ip: str = "",
        request_path: str = "",
        raw_data: str = "",
    ) -> Optional[OobCallback]:
        """
        Record a received OOB callback. Returns the callback if the
        token is valid, None otherwise.
        """
        if token_str not in self._tokens:
            logger.debug("Unknown OOB token: %s", token_str)
            return None

        token = self._tokens[token_str]
        if token.expires_at and time.monotonic() > token.expires_at:
            logger.debug("Expired OOB token: %s", token_str)
            return None

        callback = OobCallback(
            token=token_str,
            callback_type=callback_type,
            source_ip=source_ip,
            received_at=time.monotonic(),
            request_path=request_path,
            raw_data=raw_data,
        )

        self._callbacks.setdefault(token_str, []).append(callback)
        logger.info("OOB callback recorded: token=%s type=%s", token_str, callback_type)
        return callback

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, token_str: str) -> Optional[OobVerification]:
        """
        Check if a token has received any callbacks.
        """
        token = self._tokens.get(token_str)
        if not token:
            return None

        callbacks = self._callbacks.get(token_str, [])
        if not callbacks:
            return None

        first_callback = callbacks[0]
        latency = (first_callback.received_at - token.created_at) * 1000

        return OobVerification(
            token=token,
            callback=first_callback,
            confirmed=True,
            latency_ms=latency,
        )

    def verify_all(self) -> List[OobVerification]:
        """Check all registered tokens for callbacks."""
        results: List[OobVerification] = []
        for token_str in self._tokens:
            result = self.verify(token_str)
            if result:
                results.append(result)
        return results

    def get_pending(self) -> List[OobToken]:
        """Return tokens that haven't received any callbacks yet."""
        pending: List[OobToken] = []
        now = time.monotonic()
        for token_str, token in self._tokens.items():
            if token_str not in self._callbacks or not self._callbacks[token_str]:
                if not token.expires_at or now < token.expires_at:
                    pending.append(token)
        return pending

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Remove expired tokens. Returns count of removed tokens."""
        now = time.monotonic()
        expired = [
            t for t, tok in self._tokens.items()
            if tok.expires_at and now > tok.expires_at
        ]
        for t in expired:
            del self._tokens[t]
            self._callbacks.pop(t, None)
        return len(expired)

    def clear(self) -> None:
        """Remove all tokens and callbacks."""
        self._tokens.clear()
        self._callbacks.clear()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "registered_tokens": len(self._tokens),
            "tokens_with_callbacks": len(self._callbacks),
            "total_callbacks": sum(len(v) for v in self._callbacks.values()),
            "pending": len(self.get_pending()),
        }
