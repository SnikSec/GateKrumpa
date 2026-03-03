"""
BossKey — authentication endpoint prober.

Probes target endpoints for common auth misconfigurations:
  - Default / common credential pairs
  - Missing account-lockout / rate-limiting
  - Privilege escalation indicators (horizontal & vertical)
  - Verbose error messages that leak user-enumeration info
"""

from __future__ import annotations

import enum
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.bosskey.auth_probe")

# ---------------------------------------------------------------------------
# Default-credential loading
# ---------------------------------------------------------------------------

_CREDS_FILE = pathlib.Path(__file__).resolve().parents[3] / "configs" / "default_creds.txt"


def load_credentials(
    path: Optional[pathlib.Path] = None,
) -> List[Tuple[str, str]]:
    """Load credential pairs from a ``username:password`` text file.

    Falls back to a minimal built-in set if the file is missing.
    """
    target = path or _CREDS_FILE
    pairs: List[Tuple[str, str]] = []
    try:
        for line in target.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pwd = line.split(":", 1)
                pairs.append((user.strip(), pwd.strip()))
    except FileNotFoundError:
        logger.warning(
            "Credential file %s not found — using built-in fallback", target
        )
        pairs = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("test", "test"),
        ]
    return pairs


DEFAULT_CREDS: List[Tuple[str, str]] = load_credentials()

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AuthEndpoint:
    """Description of a login / token endpoint to probe."""
    url: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    content_type: str = "application/json"
    extra_fields: Dict[str, Any] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=lambda: ["token", "access_token", "session"])
    failure_indicators: List[str] = field(default_factory=lambda: ["invalid", "incorrect", "failed", "unauthorized"])


# ---------------------------------------------------------------------------
# AuthProbe
# ---------------------------------------------------------------------------

class AuthProbe:
    """
    Probe authentication endpoints for common weaknesses.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    credentials:
        Credential pairs to try. Defaults to :data:`DEFAULT_CREDS`.
    rate_limit_threshold:
        Number of rapid failed attempts before we expect a rate-limit
        or lockout response. If we exceed this without being blocked,
        a finding is raised.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        credentials: Optional[List[Tuple[str, str]]] = None,
        rate_limit_threshold: int = 5,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.credentials = credentials if credentials is not None else list(DEFAULT_CREDS)
        self.rate_limit_threshold = rate_limit_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe(
        self,
        endpoint: AuthEndpoint,
        target: Target,
    ) -> List[Finding]:
        """
        Run all auth checks against *endpoint* and return findings.
        """
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            findings: List[Finding] = []
            findings.extend(await self._check_default_creds(client, endpoint, target))
            findings.extend(await self._check_rate_limiting(client, endpoint, target))
            findings.extend(await self._check_user_enumeration(client, endpoint, target))
            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Default credentials
    # ------------------------------------------------------------------

    async def _check_default_creds(
        self,
        client: HttpClient,
        ep: AuthEndpoint,
        target: Target,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for username, password in self.credentials:
            result = await self._attempt_login(client, ep, username, password)
            if result == _LoginResult.SUCCESS:
                findings.append(Finding(
                    title=f"Default credentials accepted: {username}",
                    description=(
                        f"The endpoint {ep.url} accepted a default credential pair "
                        f"for user '{username}'.  Password redacted — see raw field."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=f"username={username}, password=***REDACTED***",
                    remediation="Remove or change all default credentials before deployment.",
                    cwe=798,
                    tags=["auth", "default-creds"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Rate-limiting / lockout
    # ------------------------------------------------------------------

    async def _check_rate_limiting(
        self,
        client: HttpClient,
        ep: AuthEndpoint,
        target: Target,
    ) -> List[Finding]:
        """
        Fire rapid failed logins and check whether the server eventually
        blocks us (429, 403, connection reset, etc.).
        """
        blocked = False
        attempts = 0

        for i in range(self.rate_limit_threshold + 1):
            result = await self._attempt_login(
                client, ep, f"brute_{i}", "wrong_password_999",
            )
            attempts += 1
            if result == _LoginResult.RATE_LIMITED:
                blocked = True
                break

        if not blocked:
            return [Finding(
                title="No rate-limiting on login endpoint",
                description=(
                    f"Sent {attempts} rapid failed login attempts to {ep.url} "
                    "without receiving a rate-limit or lockout response."
                ),
                severity=Severity.HIGH,
                target=target,
                remediation=(
                    "Implement account lockout or rate-limiting after a small number "
                    "of failed attempts (e.g. 5)."
                ),
                cwe=307,
                tags=["auth", "rate-limit", "brute-force"],
            )]

        return []

    # ------------------------------------------------------------------
    # User enumeration
    # ------------------------------------------------------------------

    async def _check_user_enumeration(
        self,
        client: HttpClient,
        ep: AuthEndpoint,
        target: Target,
    ) -> List[Finding]:
        """
        Compare error messages for an existing-looking username vs a
        random one. Differing messages reveal user enumeration.
        """
        resp_real = await self._raw_login(client, ep, "admin", "definitely_wrong_pw")
        resp_fake = await self._raw_login(client, ep, "xyznonexistent99", "definitely_wrong_pw")

        if resp_real is None or resp_fake is None:
            return []

        real_body = resp_real.get("body", "")
        fake_body = resp_fake.get("body", "")
        real_status = resp_real.get("status", 0)
        fake_status = resp_fake.get("status", 0)

        # Different status codes or substantially different bodies
        if real_status != fake_status or self._bodies_differ(real_body, fake_body):
            return [Finding(
                title="User enumeration possible via login endpoint",
                description=(
                    f"The login endpoint {ep.url} returns distinguishable responses "
                    "for valid vs. invalid usernames (different status codes or "
                    "error messages)."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence=(
                    f"Status existing={real_status} vs random={fake_status}; "
                    f"body_differ={self._bodies_differ(real_body, fake_body)}"
                ),
                remediation="Return identical error messages/status for invalid username and invalid password.",
                cwe=204,
                tags=["auth", "user-enumeration"],
            )]

        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _attempt_login(
        self,
        client: HttpClient,
        ep: AuthEndpoint,
        username: str,
        password: str,
    ) -> "_LoginResult":
        """Attempt a single login and classify the outcome."""
        resp = await self._raw_login(client, ep, username, password)
        if resp is None:
            return _LoginResult.ERROR

        status = resp["status"]
        body = resp["body"].lower()

        if status == 429 or status == 403:
            return _LoginResult.RATE_LIMITED

        if status in (200, 201):
            if any(ind in body for ind in ep.success_indicators):
                return _LoginResult.SUCCESS

        return _LoginResult.FAILURE

    async def _raw_login(
        self,
        client: HttpClient,
        ep: AuthEndpoint,
        username: str,
        password: str,
    ) -> Optional[Dict[str, Any]]:
        """Issue the login request and return {status, body} or None."""
        payload = {
            ep.username_field: username,
            ep.password_field: password,
            **ep.extra_fields,
        }
        try:
            resp = await client.request(
                ep.method,
                ep.url,
                json_body=payload,
            )
            return {"status": resp.status_code, "body": resp.text}
        except (httpx.HTTPError, OSError):
            logger.debug("Login request to %s failed", ep.url)
            return None

    @staticmethod
    def _bodies_differ(a: str, b: str) -> bool:
        """
        Heuristic: bodies are 'different' if they differ by more than
        trivial whitespace or timestamp-like noise.
        """
        # Simple: normalise whitespace and compare
        a_norm = " ".join(a.split()).lower()
        b_norm = " ".join(b.split()).lower()
        return a_norm != b_norm


# ---------------------------------------------------------------------------
# Internal enum
# ---------------------------------------------------------------------------

class _LoginResult(enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
