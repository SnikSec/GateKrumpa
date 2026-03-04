"""
OpenKrump — BOLA / IDOR test-case generator.

Analyses OpenAPI specs to identify endpoints with path parameters that
are likely to be vulnerable to **Broken Object Level Authorization**
(BOLA / IDOR) attacks:

* Endpoints with ``{id}``-style path parameters
* Object-level access patterns (GET /users/{id}, DELETE /orders/{id})
* Generates test cases that swap IDs to verify authorisation enforcement
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target
from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.bola")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Parameter name patterns that indicate an object identifier
_ID_PARAM_PATTERNS = [
    re.compile(r"^id$", re.IGNORECASE),
    re.compile(r"_id$", re.IGNORECASE),
    re.compile(r"Id$"),
    re.compile(r"^uuid$", re.IGNORECASE),
    re.compile(r"^slug$", re.IGNORECASE),
    re.compile(r"^key$", re.IGNORECASE),
    re.compile(r"^ref$", re.IGNORECASE),
    re.compile(r"^number$", re.IGNORECASE),
]

# Path segment patterns indicating object-level resources
_RESOURCE_PATH_PATTERNS = [
    re.compile(r"/\{[^}]+\}(?:/|$)"),           # /users/{id}
    re.compile(r"/\d+(?:/|$)"),                   # /users/123
]

# Default alternate IDs for testing IDOR
_TEST_IDS: Dict[str, List[str]] = {
    "integer": ["1", "2", "99999", "0", "-1"],
    "uuid": [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    ],
    "string": ["admin", "test", "other_user"],
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BolaTestCase:
    """A single BOLA/IDOR test case."""
    endpoint: ParsedEndpoint
    param_name: str
    original_value: str
    test_value: str
    method: str = "GET"
    description: str = ""
    url_template: str = ""

    @property
    def full_id(self) -> str:
        return f"{self.method} {self.url_template} [{self.param_name}={self.test_value}]"


@dataclass
class BolaCheckResult:
    """Result of executing a BOLA test case."""
    test_case: BolaTestCase
    original_status: int
    test_status: int
    original_body_length: int
    test_body_length: int
    access_granted: bool = False


# ---------------------------------------------------------------------------
# BolaGenerator
# ---------------------------------------------------------------------------

class BolaGenerator:
    """Generate and optionally execute BOLA/IDOR test cases from a spec.

    Parameters
    ----------
    alternate_ids:
        Custom mapping of ID types to test values. Merged with defaults.
    """

    def __init__(
        self,
        *,
        alternate_ids: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self._test_ids = dict(_TEST_IDS)
        if alternate_ids:
            for k, v in alternate_ids.items():
                self._test_ids.setdefault(k, []).extend(v)

    # ------------------------------------------------------------------
    # Static analysis — generate test cases from spec
    # ------------------------------------------------------------------

    def generate(self, endpoints: List[ParsedEndpoint]) -> List[BolaTestCase]:
        """Identify BOLA-susceptible endpoints and produce test cases."""
        test_cases: List[BolaTestCase] = []

        for ep in endpoints:
            id_params = self._find_id_params(ep)
            if not id_params:
                continue

            for param_name, param_type in id_params:
                test_values = self._test_ids.get(param_type, self._test_ids["string"])
                original = self._default_value(param_type)

                for tv in test_values:
                    if tv == original:
                        continue
                    test_cases.append(BolaTestCase(
                        endpoint=ep,
                        param_name=param_name,
                        original_value=original,
                        test_value=tv,
                        method=ep.method,
                        url_template=ep.path,
                        description=(
                            f"BOLA test: {ep.method} {ep.path} with "
                            f"{param_name}={tv} (original: {original})"
                        ),
                    ))

        logger.info("Generated %d BOLA test cases from %d endpoints",
                     len(test_cases), len(endpoints))
        return test_cases

    def analyse_endpoints(self, endpoints: List[ParsedEndpoint]) -> List[Finding]:
        """Static analysis: flag endpoints that are BOLA-susceptible.

        Does NOT send HTTP requests — just identifies risky patterns.
        """
        findings: List[Finding] = []
        seen: Set[str] = set()

        for ep in endpoints:
            id_params = self._find_id_params(ep)
            if not id_params:
                continue

            key = f"{ep.method} {ep.path}"
            if key in seen:
                continue
            seen.add(key)

            param_names = [name for name, _ in id_params]
            has_security = bool(ep.security)

            severity = Severity.MEDIUM if has_security else Severity.HIGH

            findings.append(Finding(
                title=f"BOLA-susceptible endpoint: {ep.method} {ep.path}",
                description=(
                    f"The endpoint {ep.method} {ep.path} uses path parameter(s) "
                    f"{', '.join(param_names)} that reference object identifiers. "
                    f"{'Security definitions are present.' if has_security else 'No security definitions found — higher risk.'} "
                    "This endpoint should be tested for Broken Object Level Authorization."
                ),
                severity=severity,
                target=Target(url=ep.path, method=ep.method),
                remediation=(
                    "Implement object-level authorization checks. Verify the "
                    "authenticated user owns or has permission to access the "
                    "requested resource before returning it."
                ),
                cwe=639,
                tags=["auth", "bola", "idor", "api"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Parameter classification
    # ------------------------------------------------------------------

    def _find_id_params(
        self, endpoint: ParsedEndpoint,
    ) -> List[tuple]:
        """Find path parameters that look like object identifiers.

        Returns list of ``(param_name, param_type)`` tuples.
        """
        results: List[tuple] = []

        # Check explicit parameters
        for param in endpoint.parameters:
            if param.get("in") != "path":
                continue
            name = param.get("name", "")
            if self._is_id_param(name):
                param_type = self._classify_type(param)
                results.append((name, param_type))

        # Also check path template for implicit parameters
        path_params = re.findall(r"\{(\w+)\}", endpoint.path)
        explicit_names = {name for name, _ in results}
        for pp in path_params:
            if pp not in explicit_names and self._is_id_param(pp):
                results.append((pp, "string"))

        return results

    @staticmethod
    def _is_id_param(name: str) -> bool:
        """Check if a parameter name looks like an object identifier."""
        return any(p.search(name) for p in _ID_PARAM_PATTERNS)

    @staticmethod
    def _classify_type(param: Dict[str, Any]) -> str:
        """Classify a parameter as integer, uuid, or string."""
        schema = param.get("schema", param)
        param_type = schema.get("type", "")
        param_format = schema.get("format", "")

        if param_format == "uuid" or param_type == "uuid":
            return "uuid"
        if param_type == "integer" or param_format in ("int32", "int64"):
            return "integer"
        return "string"

    @staticmethod
    def _default_value(param_type: str) -> str:
        """Return a plausible default/original value for testing."""
        if param_type == "integer":
            return "1"
        elif param_type == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return "current_user"
