"""
WaaaghLogic — Numeric precision abuse testing.

Float rounding, integer overflow, scientific notation, and
currency rounding attacks.

CWE-190: Integer Overflow
CWE-681: Incorrect Conversion between Numeric Types
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.numeric_precision")


# Integer overflow payloads
_INTEGER_OVERFLOW_VALUES: List[Dict[str, Any]] = [
    {"label": "Max int32", "value": 2147483647},
    {"label": "Max int32 + 1", "value": 2147483648},
    {"label": "Max int64", "value": 9223372036854775807},
    {"label": "Max int64 + 1 (string)", "value": "9223372036854775808"},
    {"label": "Min int32", "value": -2147483648},
    {"label": "Min int32 - 1", "value": -2147483649},
    {"label": "Max uint32", "value": 4294967295},
    {"label": "Max uint32 + 1", "value": 4294967296},
]

# Float precision payloads
_FLOAT_PRECISION_VALUES: List[Dict[str, Any]] = [
    {"label": "0.1 + 0.2 ≠ 0.3", "value": 0.30000000000000004},
    {"label": "Tiny positive", "value": 0.0000001},
    {"label": "Many decimals", "value": 0.99999999999999999},
    {"label": "Large float", "value": 1e308},
    {"label": "-Large float", "value": -1e308},
    {"label": "Denormalized float", "value": 5e-324},
    {"label": "Negative epsilon", "value": -2.220446049250313e-16},
]

# Scientific notation payloads
_SCIENTIFIC_NOTATION_VALUES: List[Dict[str, Any]] = [
    {"label": "1e2 (100)", "value": "1e2"},
    {"label": "1e-7 (tiny)", "value": "1e-7"},
    {"label": "1e308 (huge)", "value": "1e308"},
    {"label": "1e309 (overflow)", "value": "1e309"},
    {"label": "0e0 (zero)", "value": "0e0"},
    {"label": "1E2 (uppercase)", "value": "1E2"},
    {"label": "1.5e3", "value": "1.5e3"},
]

# Currency-specific rounding payloads
_CURRENCY_ROUNDING_VALUES: List[Dict[str, Any]] = [
    {"label": "Half-cent rounding", "value": 0.005},
    {"label": "Sub-cent value", "value": 0.001},
    {"label": "Negative half-cent", "value": -0.005},
    {"label": "Many small amounts", "count": 100, "value": 0.004},
    {"label": "Banker's rounding edge", "value": 2.5},
    {"label": "Fraction of cent", "value": 0.009},
]


class NumericPrecisionTester:
    """
    Test endpoints for numeric precision abuse:
      1. Integer overflow / underflow at boundaries
      2. Float precision exploitation
      3. Scientific notation bypass
      4. Currency rounding abuse (salami attack)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def test(self, target: Target) -> List[Finding]:
        """Run all numeric precision tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            findings.extend(await self._test_integer_overflow(client, target))
            findings.extend(await self._test_float_precision(client, target))
            findings.extend(await self._test_scientific_notation(client, target))
            findings.extend(await self._test_currency_rounding(client, target))
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_integer_overflow(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send integer boundary values to detect overflow/truncation."""
        findings: List[Finding] = []
        test_fields = ["id", "quantity", "amount", "count", "limit", "offset", "page"]

        for field_name in test_fields:
            for payload in _INTEGER_OVERFLOW_VALUES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Integer overflow crash ({payload['label']}) on {target.url}",
                            description=(
                                f"Sending {payload['label']} ({payload['value']}) for "
                                f"field '{field_name}' triggered a server error. "
                                f"Integer overflow can cause unexpected wrapping, "
                                f"negative values from unsigned overflow, or crashes."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}={payload['value']}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Use appropriate data types (BigInteger for unbounded). "
                                "Validate ranges before arithmetic operations. "
                                "Handle overflow explicitly."
                            ),
                            cwe=190,
                            tags=["numeric", "integer-overflow", "waaaghlogic"],
                        ))
                        return findings
                    # Check if value wraps (positive becomes negative)
                    if resp.status_code in (200, 201) and payload["value"] > 0:
                        try:
                            resp_data = json.loads(resp.text)
                            if isinstance(resp_data, dict):
                                for key, val in resp_data.items():
                                    if isinstance(val, (int, float)) and val < 0:
                                        findings.append(Finding(
                                            title=f"Integer wrap-around detected on {target.url}",
                                            description=(
                                                f"Sending large positive value {payload['value']} "
                                                f"for '{field_name}' resulted in negative value "
                                                f"{val} in response field '{key}', indicating "
                                                f"integer overflow/truncation."
                                            ),
                                            severity=Severity.HIGH,
                                            target=target,
                                            evidence=(
                                                f"Input: {field_name}={payload['value']}\n"
                                                f"Output: {key}={val}"
                                            ),
                                            remediation=(
                                                "Use 64-bit integers or BigInteger. "
                                                "Validate input ranges match database column types."
                                            ),
                                            cwe=190,
                                            tags=["numeric", "integer-overflow", "waaaghlogic"],
                                        ))
                                        return findings
                        except (json.JSONDecodeError, AttributeError):
                            pass
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_float_precision(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test float precision edge cases."""
        findings: List[Finding] = []
        test_fields = ["price", "amount", "total", "rate", "tax"]

        for field_name in test_fields:
            for payload in _FLOAT_PRECISION_VALUES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code >= 500:
                        findings.append(Finding(
                            title=f"Float edge case crash ({payload['label']}) on {target.url}",
                            description=(
                                f"Sending {payload['label']} for '{field_name}' "
                                f"triggered a server error. Extreme float values "
                                f"can cause arithmetic overflow or database errors."
                            ),
                            severity=Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Field: {field_name}={payload['value']}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Use decimal types for financial calculations. "
                                "Validate float ranges and reject special values."
                            ),
                            cwe=681,
                            tags=["numeric", "float-precision", "waaaghlogic"],
                        ))
                        return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_scientific_notation(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Send scientific notation to bypass string-based numeric filters."""
        findings: List[Finding] = []
        test_fields = ["price", "amount", "quantity", "id"]

        for field_name in test_fields:
            for payload in _SCIENTIFIC_NOTATION_VALUES:
                body = {field_name: payload["value"]}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code in (200, 201, 202):
                        # Check if scientific notation was interpreted
                        text = resp.text
                        if payload["value"] == "1e309" and ("inf" in text.lower() or "overflow" in text.lower()):
                            findings.append(Finding(
                                title=f"Scientific notation accepted on {target.url}",
                                description=(
                                    f"The endpoint accepted scientific notation "
                                    f"'{payload['value']}' for '{field_name}'. "
                                    f"This can bypass string-based input filters "
                                    f"and cause overflow when parsed as a number."
                                ),
                                severity=Severity.LOW,
                                target=target,
                                evidence=(
                                    f"Field: {field_name}={payload['value']}\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Response snippet: {text[:200]}"
                                ),
                                remediation=(
                                    "Parse numeric inputs strictly. Reject scientific "
                                    "notation in fields expecting plain integers. "
                                    "Use allow-list regex for numeric formats."
                                ),
                                cwe=681,
                                tags=["numeric", "scientific-notation", "waaaghlogic"],
                            ))
                            return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_currency_rounding(
        self, client: HttpClient, target: Target,
    ) -> List[Finding]:
        """Test sub-cent amounts for rounding abuse (salami attack)."""
        findings: List[Finding] = []
        test_fields = ["price", "amount", "total", "payment"]

        for field_name in test_fields:
            for payload in _CURRENCY_ROUNDING_VALUES:
                value = payload["value"]
                body = {field_name: value}
                try:
                    resp = await client.request(
                        target.method or "POST", target.url, json_body=body,
                    )
                    if resp.status_code in (200, 201, 202):
                        # Check if the value was rounded to zero
                        try:
                            data = json.loads(resp.text)
                            if isinstance(data, dict):
                                for key, val in data.items():
                                    if isinstance(val, (int, float)):
                                        if val == 0 and value > 0:
                                            findings.append(Finding(
                                                title=f"Currency rounding to zero on {target.url}",
                                                description=(
                                                    f"Sending amount={value} resulted in "
                                                    f"{key}=0 in the response. Sub-cent "
                                                    f"values rounded to zero could be "
                                                    f"exploited in 'salami attack' scenarios "
                                                    f"via many small transactions."
                                                ),
                                                severity=Severity.MEDIUM,
                                                target=target,
                                                evidence=(
                                                    f"Input: {field_name}={value}\n"
                                                    f"Output: {key}={val}"
                                                ),
                                                remediation=(
                                                    "Use fixed-point decimal types for all "
                                                    "monetary values. Round consistently "
                                                    "(banker's rounding). Reject sub-cent "
                                                    "amounts at the API level."
                                                ),
                                                cwe=681,
                                                tags=["numeric", "currency-rounding", "waaaghlogic"],
                                            ))
                                            return findings
                        except (json.JSONDecodeError, AttributeError):
                            pass
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings
