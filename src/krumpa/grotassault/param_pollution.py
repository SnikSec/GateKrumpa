"""
GrotAssault — HTTP Parameter Pollution (HPP) checker.

Tests for HPP by sending duplicate parameters and observing which value
the server uses.  Different web frameworks handle duplicates differently
(first-wins, last-wins, concatenation), making HPP useful for:
  - WAF / filter bypass
  - Business logic manipulation
  - Authentication bypass

References:
  - CWE-235: Improper Handling of Extra Parameters
  - OWASP Testing Guide: OTG-INPVAL-004
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlunparse

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.grotassault.param_pollution")


# Typical HPP test cases
_HPP_PROBES: List[Dict[str, Any]] = [
    {
        "name": "duplicate_same_value",
        "params": [("krumpa_test", "first"), ("krumpa_test", "second")],
        "description": "Duplicate parameter with different values",
    },
    {
        "name": "array_index_override",
        "params": [("id", "1"), ("id", "2")],
        "description": "Duplicate 'id' parameter — may bypass access controls",
    },
    {
        "name": "bracket_array",
        "params": [("items[]", "1"), ("items[]", "2")],
        "description": "PHP/Rails-style array parameters",
    },
]


class ParamPollutionChecker(HttpClientMixin):
    """Test endpoints for HTTP Parameter Pollution vulnerabilities."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def check(self, target: Target) -> List[Finding]:
        """Inject duplicate parameters and observe server behaviour."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            # Parse existing query string parameters
            parsed = urlparse(target.url)
            existing_params = parse_qs(parsed.query, keep_blank_values=True)

            if not existing_params:
                # No query params — synthesize probe on common param names
                findings.extend(await self._probe_synthetic(client, target))
                return findings

            # For each existing parameter, send a duplicate
            for param_name, param_values in existing_params.items():
                finding = await self._test_duplicate(
                    client, target, param_name, param_values[0],
                )
                if finding:
                    findings.append(finding)
                    break  # one finding per target

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_duplicate(
        self,
        client: HttpClient,
        target: Target,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Duplicate *param_name* with a canary and observe the response."""
        canary = "krumpa_hpp_canary"

        # Build URL with duplicate param
        parsed = urlparse(target.url)
        # Append duplicate parameter
        new_query = f"{parsed.query}&{param_name}={canary}" if parsed.query else f"{param_name}={canary}"
        polluted_url = urlunparse(parsed._replace(query=new_query))

        try:
            # Baseline
            baseline_resp = await client.get(target.url)

            # Polluted
            polluted_resp = await client.get(polluted_url)

            # Analysis
            if canary in polluted_resp.text and canary not in baseline_resp.text:
                return Finding(
                    title=f"HTTP Parameter Pollution on {target.url}",
                    description=(
                        f"Duplicating parameter '{param_name}' with a canary value "
                        f"caused the canary to appear in the response. The server "
                        f"may use the last value (last-wins) or concatenate duplicates, "
                        f"enabling filter bypass or logic manipulation."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Parameter: {param_name}\n"
                        f"Original: {original_value}\n"
                        f"Injected: {canary}\n"
                        f"Canary reflected in response"
                    ),
                    remediation=(
                        "Ensure the application explicitly handles duplicate parameters "
                        "(pick first or reject duplicates). Do not rely on framework "
                        "defaults for parameter precedence."
                    ),
                    cwe=235,
                    tags=["param-pollution", "hpp", "grotassault"],
                )

            # Check if status code changed significantly
            if (
                polluted_resp.status_code != baseline_resp.status_code
                and polluted_resp.status_code in (200, 302)
                and baseline_resp.status_code in (401, 403)
            ):
                return Finding(
                    title=f"HPP bypasses access control on {target.url}",
                    description=(
                        f"Duplicating parameter '{param_name}' changed the response "
                        f"status from {baseline_resp.status_code} to "
                        f"{polluted_resp.status_code}, suggesting an access control bypass."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=(
                        f"Baseline: {baseline_resp.status_code}\n"
                        f"Polluted: {polluted_resp.status_code}"
                    ),
                    remediation=(
                        "Validate parameters strictly. Reject requests with "
                        "duplicate parameters. Apply access controls consistently."
                    ),
                    cwe=235,
                    tags=["param-pollution", "hpp", "auth-bypass", "grotassault"],
                )

        except (httpx.HTTPError, OSError, ValueError):
            pass

        return None

    async def _probe_synthetic(
        self,
        client: HttpClient,
        target: Target,
    ) -> List[Finding]:
        """Probe with synthetic duplicate parameters when no query string exists."""
        findings: List[Finding] = []

        for probe in _HPP_PROBES:
            params = probe["params"]
            query = "&".join(f"{k}={v}" for k, v in params)
            parsed = urlparse(target.url)
            test_url = urlunparse(parsed._replace(query=query))

            try:
                resp = await client.get(test_url)

                # Check for duplicate handling indicators
                values = [v for _, v in params]
                # Concatenation detection (e.g., "first,second" or "firstsecond")
                concat_patterns = [
                    f"{values[0]},{values[1]}",
                    f"{values[0]}, {values[1]}",
                    f"{values[0]}{values[1]}",
                ]
                for pattern in concat_patterns:
                    if pattern in resp.text:
                        findings.append(Finding(
                            title=f"Parameter concatenation detected on {target.url}",
                            description=(
                                f"Probe '{probe['name']}' ({probe['description']}) "
                                f"shows the server concatenates duplicate parameters: "
                                f"'{pattern}'. This behaviour can be exploited for HPP."
                            ),
                            severity=Severity.LOW,
                            target=target,
                            evidence=f"Params: {query}\nConcat: {pattern}",
                            remediation=(
                                "Use the first parameter value only or reject "
                                "duplicate parameters."
                            ),
                            cwe=235,
                            tags=["param-pollution", "hpp", "concat", "grotassault"],
                        ))
                        break

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings
