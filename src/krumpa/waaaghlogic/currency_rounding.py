"""Currency rounding exploitation — float rounding attacks on monetary values.

Phase 4 item #55.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target


@dataclass
class RoundingTestResult:
    """Result of a single rounding test."""
    test_name: str
    sent_value: Any
    received_total: Optional[float] = None
    expected_total: Optional[float] = None
    discrepancy: float = 0.0
    exploitable: bool = False
    evidence: str = ""


# Rounding-exploitable values — amounts that different rounding modes handle differently
ROUNDING_PAYLOADS = [
    # Classic half-cent rounding
    {"value": 0.005, "qty": 1, "label": "Half-cent rounding (0.005)"},
    {"value": 0.015, "qty": 1, "label": "1.5 cents (0.015) — banker's rounding edge"},
    {"value": 0.025, "qty": 1, "label": "2.5 cents (0.025)"},
    {"value": 0.995, "qty": 100, "label": "99.5 cents × 100 — accumulated error"},
    {"value": 0.004999, "qty": 1000, "label": "Sub-cent × 1000 — many small errors"},
    {"value": 0.001, "qty": 10000, "label": "Sub-cent × 10000 — salami slicing"},
    # Float precision limitations
    {"value": 0.1 + 0.2, "qty": 1, "label": "0.1+0.2 float precision (0.30000000000000004)"},
    {"value": 9999999.99, "qty": 1, "label": "Large amount precision"},
    {"value": 0.0001, "qty": 100000, "label": "Micro-cent × 100k — sub-penny accumulation"},
    # Scientific notation
    {"value": 1e-10, "qty": 1, "label": "Scientific notation near-zero"},
    {"value": 1.0000000001, "qty": 1, "label": "Just over 1.00 — precision test"},
    # Negative rounding edge cases
    {"value": -0.005, "qty": 1, "label": "Negative half-cent (refund rounding)"},
    {"value": -0.001, "qty": 1000, "label": "Negative micro-cent × 1000"},
]

# Currency format edge cases
CURRENCY_CONFUSION_PAYLOADS = [
    {"amount": "9,99", "currency": "EUR", "label": "Comma as decimal (European)"},
    {"amount": "9.99", "currency": "JPY", "label": "JPY has no decimal places"},
    {"amount": "999", "currency": "BHD", "label": "BHD has 3 decimal places"},
    {"amount": "0.999", "currency": "USD", "label": "Three decimal places in USD"},
    {"amount": "1E2", "currency": "USD", "label": "Scientific notation as amount"},
    {"amount": "Infinity", "currency": "USD", "label": "Infinity as amount"},
    {"amount": "NaN", "currency": "USD", "label": "NaN as amount"},
]


class CurrencyRoundingTester:
    """Test for currency rounding exploitation vulnerabilities.

    Attack vectors:
    - Salami slicing (accumulate fractional cents)
    - Rounding mode inconsistency (banker's vs. half-up vs. truncation)
    - Float precision exploitation (0.1 + 0.2 != 0.3)
    - Currency format confusion (comma vs. dot, decimal place count)
    - Quantity × price rounding order (multiply then round vs. round then multiply)
    - Discount/tax rounding chain errors
    """

    def __init__(
        self,
        cart_endpoint: Optional[str] = None,
        order_endpoint: Optional[str] = None,
        price_field: str = "price",
        total_field: str = "total",
    ) -> None:
        self._cart_endpoint = cart_endpoint
        self._order_endpoint = order_endpoint
        self._price_field = price_field
        self._total_field = total_field
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all currency rounding tests."""
        findings: List[Finding] = []
        url = target.url

        # 1. Rounding accumulation attacks
        findings.extend(await self._test_rounding_accumulation(url, target))

        # 2. Float precision exploitation
        findings.extend(await self._test_float_precision(url, target))

        # 3. Currency format confusion
        findings.extend(await self._test_currency_confusion(url, target))

        # 4. Discount chain rounding
        findings.extend(await self._test_discount_rounding(url, target))

        # 5. Quantity-price rounding order
        findings.extend(await self._test_rounding_order(url, target))

        return findings

    # ----------------------------------------------------------
    # Rounding accumulation
    # ----------------------------------------------------------

    async def _test_rounding_accumulation(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test salami-slicing via accumulated rounding errors."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        endpoints = self._get_endpoints(url)

        for payload in ROUNDING_PAYLOADS:
            value = payload["value"]
            qty = payload["qty"]
            label = payload["label"]

            for endpoint in endpoints:
                body = {
                    self._price_field: value,
                    "quantity": qty,
                    "product_id": "test-rounding",
                }

                try:
                    resp = await self._client.request(
                        "POST", endpoint, json_body=body,
                    )

                    if resp.status_code not in (200, 201):
                        continue

                    try:
                        resp_body = json.loads(resp.text)
                        actual_total = self._extract_total(resp_body)
                        if actual_total is None:
                            continue

                        # Calculate what we'd expect with proper rounding
                        expected_total = round(value * qty, 2)
                        discrepancy = abs(actual_total - expected_total)

                        if discrepancy > 0.001:
                            exploitable = discrepancy > 0.01
                            findings.append(Finding(
                                title=f"Currency rounding discrepancy: {label}",
                                description=(
                                    f"Sent {self._price_field}={value} × qty={qty}. "
                                    f"Expected total: {expected_total:.4f}, "
                                    f"got: {actual_total:.4f}. "
                                    f"Discrepancy: {discrepancy:.6f}. "
                                    f"This rounding inconsistency can be exploited "
                                    f"at scale via accumulated micro-cent errors."
                                ),
                                severity=Severity.HIGH if exploitable else Severity.LOW,
                                target=target,
                                evidence=(
                                    f"Input: {value} × {qty} = {value * qty:.10f}\n"
                                    f"Expected (rounded): {expected_total}\n"
                                    f"Actual: {actual_total}\n"
                                    f"Discrepancy: {discrepancy:.6f}"
                                ),
                                remediation=(
                                    "Use integer arithmetic (cents/pennies) internally. "
                                    "Apply consistent rounding (banker's rounding / "
                                    "ROUND_HALF_EVEN) at the final display step only. "
                                    "Never use floating-point for monetary calculations."
                                ),
                                cwe=681,
                                tags=["currency", "rounding", "salami-slicing", "waaaghlogic"],
                            ))
                            break  # One hit per payload

                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Float precision
    # ----------------------------------------------------------

    async def _test_float_precision(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test float precision edge cases in monetary calculations."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        endpoints = self._get_endpoints(url)

        # Classic IEEE 754 precision failure
        precision_tests = [
            {"prices": [0.1, 0.2], "expected": 0.3, "label": "0.1 + 0.2 !== 0.3"},
            {"prices": [19.99, 20.01], "expected": 40.00, "label": "19.99 + 20.01"},
            {"prices": [0.01] * 100, "expected": 1.00, "label": "0.01 × 100"},
            {"prices": [33.33, 33.33, 33.34], "expected": 100.00, "label": "Three-way split of 100"},
        ]

        for test in precision_tests:
            for endpoint in endpoints:
                items = [
                    {"product_id": f"fp-{i}", self._price_field: p, "quantity": 1}
                    for i, p in enumerate(test["prices"])
                ]
                body = {"items": items}

                try:
                    resp = await self._client.request(
                        "POST", endpoint, json_body=body,
                    )

                    if resp.status_code not in (200, 201):
                        continue

                    try:
                        resp_body = json.loads(resp.text)
                        actual_total = self._extract_total(resp_body)
                        if actual_total is None:
                            continue

                        expected = test["expected"]
                        discrepancy = abs(actual_total - expected)

                        if discrepancy > 0.001:
                            findings.append(Finding(
                                title=f"Float precision error: {test['label']}",
                                description=(
                                    f"Items priced at {test['prices']} should total "
                                    f"{expected}, but server returned {actual_total}. "
                                    f"This indicates floating-point arithmetic is used "
                                    f"for monetary calculations."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Prices: {test['prices']}\n"
                                    f"Expected: {expected}\n"
                                    f"Actual: {actual_total}\n"
                                    f"Discrepancy: {discrepancy:.10f}"
                                ),
                                remediation=(
                                    "Use integer-based or Decimal-based arithmetic "
                                    "for all monetary calculations. Never use float/double."
                                ),
                                cwe=681,
                                tags=["currency", "float-precision", "waaaghlogic"],
                            ))
                            break

                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Currency confusion
    # ----------------------------------------------------------

    async def _test_currency_confusion(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test currency format and type confusion attacks."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        endpoints = self._get_endpoints(url)

        for payload in CURRENCY_CONFUSION_PAYLOADS:
            for endpoint in endpoints:
                body = {
                    "amount": payload["amount"],
                    "currency": payload["currency"],
                    "product_id": "currency-test",
                    "quantity": 1,
                }

                try:
                    resp = await self._client.request(
                        "POST", endpoint, json_body=body,
                    )

                    if resp.status_code in (200, 201):
                        text = resp.text.lower()
                        if "error" not in text and "invalid" not in text:
                            findings.append(Finding(
                                title=f"Currency confusion accepted: {payload['label']}",
                                description=(
                                    f"The server accepted {payload['amount']} in "
                                    f"{payload['currency']} without rejection. "
                                    f"{payload['label']}. "
                                    f"This may exploit format or decimal place differences."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Amount: {payload['amount']}\n"
                                    f"Currency: {payload['currency']}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Validate currency codes against ISO 4217. "
                                    "Apply currency-specific decimal rules (JPY=0, BHD=3, USD=2). "
                                    "Reject NaN, Infinity, and scientific notation."
                                ),
                                cwe=681,
                                tags=["currency", "confusion", "waaaghlogic"],
                            ))
                            break

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Discount rounding chain
    # ----------------------------------------------------------

    async def _test_discount_rounding(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test rounding order in discount/tax chains."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        endpoints = self._get_endpoints(url)

        # item_price → apply discount → apply tax → total
        # vs. item_price → apply tax → apply discount → total
        # Different rounding at each step = different totals

        discount_scenarios = [
            {
                "item_price": 9.99,
                "discount_pct": 33.33,
                "tax_pct": 8.875,
                "label": "33.33% discount + 8.875% tax on $9.99",
            },
            {
                "item_price": 1.01,
                "discount_pct": 50,
                "tax_pct": 7,
                "label": "50% discount + 7% tax on $1.01 (odd cent split)",
            },
            {
                "item_price": 0.03,
                "discount_pct": 10,
                "tax_pct": 10,
                "label": "10% discount + 10% tax on $0.03 (sub-cent)",
            },
        ]

        for scenario in discount_scenarios:
            for endpoint in endpoints:
                body = {
                    self._price_field: scenario["item_price"],
                    "quantity": 1,
                    "discount_percent": scenario["discount_pct"],
                    "tax_percent": scenario["tax_pct"],
                    "product_id": "rounding-chain",
                }

                try:
                    resp = await self._client.request(
                        "POST", endpoint, json_body=body,
                    )

                    if resp.status_code not in (200, 201):
                        continue

                    try:
                        resp_body = json.loads(resp.text)
                        actual_total = self._extract_total(resp_body)
                        if actual_total is None:
                            continue

                        # Calculate expected both ways
                        price = scenario["item_price"]
                        discount = 1 - scenario["discount_pct"] / 100
                        tax = 1 + scenario["tax_pct"] / 100

                        total_discount_first = round(round(price * discount, 2) * tax, 2)
                        total_tax_first = round(round(price * tax, 2) * discount, 2)

                        if total_discount_first != total_tax_first:
                            # There's inherent ambiguity — check if server matches either
                            diff_d = abs(actual_total - total_discount_first)
                            diff_t = abs(actual_total - total_tax_first)

                            if diff_d > 0.01 and diff_t > 0.01:
                                findings.append(Finding(
                                    title=f"Rounding chain inconsistency: {scenario['label']}",
                                    description=(
                                        f"The calculated total ({actual_total}) doesn't match "
                                        f"either discount-first ({total_discount_first}) or "
                                        f"tax-first ({total_tax_first}) ordering. "
                                        f"Inconsistent rounding in multi-step calculations."
                                    ),
                                    severity=Severity.LOW,
                                    target=target,
                                    evidence=(
                                        f"Price: {price}, Discount: {scenario['discount_pct']}%, "
                                        f"Tax: {scenario['tax_pct']}%\n"
                                        f"Actual: {actual_total}\n"
                                        f"Discount-first: {total_discount_first}\n"
                                        f"Tax-first: {total_tax_first}"
                                    ),
                                    remediation=(
                                        "Define a clear calculation order (usually: "
                                        "subtotal → discount → tax → total). "
                                        "Round only once at the end."
                                    ),
                                    cwe=681,
                                    tags=["currency", "rounding-chain", "waaaghlogic"],
                                ))

                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Rounding order test
    # ----------------------------------------------------------

    async def _test_rounding_order(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test if quantity×price is rounded differently from price×quantity."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        endpoints = self._get_endpoints(url)

        # 1 item at $X.YY vs. N items at $X.YY — do they match N * single_total?
        test_cases = [
            {"price": 1.01, "qty": 3, "label": "$1.01 × 3"},
            {"price": 3.33, "qty": 3, "label": "$3.33 × 3 (9.99 vs 10.00?)"},
            {"price": 0.07, "qty": 7, "label": "$0.07 × 7"},
        ]

        for test in test_cases:
            for endpoint in endpoints:
                # Single quantity
                body_single = {
                    self._price_field: test["price"],
                    "quantity": 1,
                    "product_id": "rounding-order",
                }
                # Full quantity
                body_multi = {
                    self._price_field: test["price"],
                    "quantity": test["qty"],
                    "product_id": "rounding-order",
                }

                try:
                    resp_single = await self._client.request(
                        "POST", endpoint, json_body=body_single,
                    )
                    resp_multi = await self._client.request(
                        "POST", endpoint, json_body=body_multi,
                    )

                    if resp_single.status_code not in (200, 201):
                        continue
                    if resp_multi.status_code not in (200, 201):
                        continue

                    single_body = json.loads(resp_single.text)
                    multi_body = json.loads(resp_multi.text)

                    single_total = self._extract_total(single_body)
                    multi_total = self._extract_total(multi_body)

                    if single_total is None or multi_total is None:
                        continue

                    expected_multi = round(single_total * test["qty"], 2)
                    diff = abs(multi_total - expected_multi)

                    if diff > 0.001:
                        findings.append(Finding(
                            title=f"Rounding order inconsistency: {test['label']}",
                            description=(
                                f"Single item total ({single_total}) × {test['qty']} = "
                                f"{expected_multi}, but multi-qty total = {multi_total}. "
                                f"Difference: {diff:.4f}."
                            ),
                            severity=Severity.LOW,
                            target=target,
                            evidence=(
                                f"Single: {single_total}\n"
                                f"Multi ({test['qty']}): {multi_total}\n"
                                f"Expected multi: {expected_multi}\n"
                                f"Diff: {diff:.4f}"
                            ),
                            remediation=(
                                "Ensure consistent rounding order: price × quantity "
                                "then round, or round(price) × quantity consistently."
                            ),
                            cwe=681,
                            tags=["currency", "rounding-order", "waaaghlogic"],
                        ))
                        break

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    def _get_endpoints(self, url: str) -> List[str]:
        """Get cart/order endpoints for testing."""
        endpoints = []
        if self._cart_endpoint:
            endpoints.append(self._cart_endpoint)
        if self._order_endpoint:
            endpoints.append(self._order_endpoint)
        if not endpoints:
            endpoints = [
                f"{url}/cart/add",
                f"{url}/api/cart",
                f"{url}/api/orders",
            ]
        return endpoints

    def _extract_total(self, body: Dict[str, Any]) -> Optional[float]:
        """Extract total from response body."""
        for key in [self._total_field, "total", "amount", "grand_total", "subtotal"]:
            if key in body:
                try:
                    return float(body[key])
                except (ValueError, TypeError):
                    pass
        return None
