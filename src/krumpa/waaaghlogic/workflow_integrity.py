"""Workflow integrity testing — payment bypass, coupon reuse, gift card manipulation.

Phase 4 item #54.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class PaymentWorkflow:
    """Defines a payment/checkout workflow to test."""
    name: str
    steps: List[WorkflowStep] = field(default_factory=list)
    coupon_endpoint: Optional[str] = None
    gift_card_endpoint: Optional[str] = None


@dataclass
class WorkflowStep:
    """A single step in a payment workflow."""
    name: str
    url: str
    method: str = "POST"
    body: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    expected_status: int = 200
    price_field: Optional[str] = None  # JSON path to price field in response
    quantity_field: Optional[str] = None


@dataclass
class IntegrityViolation:
    """A detected workflow integrity violation."""
    vuln_type: str
    description: str
    severity: Severity
    evidence: str
    step_name: str


# Coupon / promo code payloads
COUPON_ABUSE_PAYLOADS = [
    {"code": "TEST100", "description": "100% off test coupon"},
    {"code": "ADMIN", "description": "Admin discount code"},
    {"code": "INTERNAL", "description": "Internal employee code"},
    {"code": "DEBUG", "description": "Debug/testing code"},
    {"code": "FREE", "description": "Free order code"},
    {"code": "EMPLOYEE", "description": "Employee discount"},
    {"code": "PROMO100", "description": "100% promotional"},
    {"code": "BLACKFRIDAY99", "description": "Extreme discount code"},
    {"code": "ZERO", "description": "Zero out total"},
    {"code": "NULL", "description": "Null coupon"},
    {"code": "", "description": "Empty coupon code"},
    {"code": "' OR 1=1--", "description": "SQLi in coupon lookup"},
    {"code": "AAAA" * 64, "description": "Overflow coupon code"},
]


class WorkflowIntegrityTester(HttpClientMixin):
    """Test payment and business workflow integrity.

    Attacks:
    - Price manipulation (client-side price override)
    - Quantity manipulation (negative, zero, fractional)
    - Step skipping (jump to confirmation without cart)
    - Coupon stacking / reuse / code injection
    - Gift card balance manipulation
    - Race condition on limited resources
    - Currency mismatch
    - Tax/shipping removal
    """

    def __init__(self, workflows: Optional[List[PaymentWorkflow]] = None) -> None:
        self._workflows = workflows or []
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all workflow integrity tests."""
        findings: List[Finding] = []
        url = target.url

        # If no explicit workflows, try to auto-detect
        if not self._workflows:
            self._workflows = self._auto_detect_workflows(url)

        for workflow in self._workflows:
            findings.extend(await self._test_price_manipulation(workflow, target))
            findings.extend(await self._test_quantity_abuse(workflow, target))
            findings.extend(await self._test_step_skipping(workflow, target))
            findings.extend(await self._test_coupon_abuse(workflow, target))
            findings.extend(await self._test_gift_card_abuse(workflow, target))
            findings.extend(await self._test_negative_total(workflow, target))

        # Generic tests that don't need workflow definition
        findings.extend(await self._test_payment_parameter_tampering(url, target))

        return findings

    # ----------------------------------------------------------
    # Auto-detection
    # ----------------------------------------------------------

    def _auto_detect_workflows(self, base_url: str) -> List[PaymentWorkflow]:
        """Build workflow templates from common e-commerce patterns."""
        workflows = []

        # Generic checkout flow
        checkout = PaymentWorkflow(
            name="Generic checkout",
            steps=[
                WorkflowStep(
                    name="add_to_cart",
                    url=f"{base_url}/cart/add",
                    method="POST",
                    body={"product_id": "1", "quantity": 1},
                ),
                WorkflowStep(
                    name="view_cart",
                    url=f"{base_url}/cart",
                    method="GET",
                    price_field="total",
                ),
                WorkflowStep(
                    name="checkout",
                    url=f"{base_url}/checkout",
                    method="POST",
                    body={"total": "0", "payment_method": "card"},
                    price_field="amount",
                ),
                WorkflowStep(
                    name="confirm",
                    url=f"{base_url}/checkout/confirm",
                    method="POST",
                    body={"confirmed": True},
                ),
            ],
            coupon_endpoint=f"{base_url}/cart/coupon",
            gift_card_endpoint=f"{base_url}/cart/gift-card",
        )
        workflows.append(checkout)

        # API-style order
        api_order = PaymentWorkflow(
            name="API order",
            steps=[
                WorkflowStep(
                    name="create_order",
                    url=f"{base_url}/api/orders",
                    method="POST",
                    body={"items": [{"id": "1", "qty": 1, "price": 9.99}]},
                    price_field="total",
                ),
                WorkflowStep(
                    name="submit_payment",
                    url=f"{base_url}/api/orders/pay",
                    method="POST",
                    body={"order_id": "", "amount": 9.99},
                ),
            ],
            coupon_endpoint=f"{base_url}/api/coupons/apply",
        )
        workflows.append(api_order)

        return workflows

    # ----------------------------------------------------------
    # Price manipulation
    # ----------------------------------------------------------

    async def _test_price_manipulation(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test if prices can be manipulated client-side."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        price_tampering_values = [
            0, -1, 0.01, 0.001, 1, -0.01,
        ]

        for step in workflow.steps:
            if not step.body or not step.price_field:
                continue

            for tampered_price in price_tampering_values:
                body = copy.deepcopy(step.body)
                self._set_nested(body, step.price_field, tampered_price)

                try:
                    resp = await self._client.request(
                        step.method, step.url,
                        json_body=body,
                        headers=step.headers,
                    )

                    if resp.status_code in (200, 201, 202):
                        try:
                            resp_body = json.loads(resp.text)
                            resp_total = self._get_nested(resp_body, step.price_field)
                            if resp_total is not None and float(resp_total) <= float(tampered_price):
                                findings.append(Finding(
                                    title=f"Price manipulation accepted in '{step.name}'",
                                    description=(
                                        f"Workflow '{workflow.name}', step '{step.name}': "
                                        f"server accepted tampered price {tampered_price} "
                                        f"(field: {step.price_field}). The response total "
                                        f"reflects the manipulated value."
                                    ),
                                    severity=Severity.CRITICAL,
                                    target=target,
                                    evidence=(
                                        f"Tampered value: {tampered_price}\n"
                                        f"Response total: {resp_total}\n"
                                        f"Status: {resp.status_code}"
                                    ),
                                    remediation=(
                                        "Never trust client-supplied prices. Calculate "
                                        "totals server-side from authoritative product data."
                                    ),
                                    cwe=472,
                                    tags=["payment", "price-manipulation", "waaaghlogic"],
                                ))
                                break  # One proof is enough
                        except (json.JSONDecodeError, ValueError):
                            pass

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Quantity abuse
    # ----------------------------------------------------------

    async def _test_quantity_abuse(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test quantity manipulation in cart/order operations."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        abuse_quantities = [
            (-1, "Negative quantity — may subtract from total"),
            (0, "Zero quantity — free item"),
            (0.5, "Fractional quantity — rounding exploitation"),
            (999999999, "Extreme quantity — integer overflow"),
            (-999999999, "Large negative — underflow attack"),
        ]

        for step in workflow.steps:
            if not step.body:
                continue

            for qty_value, description in abuse_quantities:
                body = copy.deepcopy(step.body)
                # Try setting quantity in common locations
                modified = False
                for key in ["quantity", "qty", "count", "amount"]:
                    if key in body:
                        body[key] = qty_value
                        modified = True
                    elif "items" in body and isinstance(body["items"], list):
                        for item in body["items"]:
                            if isinstance(item, dict) and "qty" in item:
                                item["qty"] = qty_value
                                modified = True

                if not modified:
                    continue

                try:
                    resp = await self._client.request(
                        step.method, step.url,
                        json_body=body,
                        headers=step.headers,
                    )

                    if resp.status_code in (200, 201, 202):
                        # Server accepted the abusive quantity
                        findings.append(Finding(
                            title=f"Quantity abuse accepted: {description}",
                            description=(
                                f"Workflow '{workflow.name}', step '{step.name}': "
                                f"server accepted quantity={qty_value}. "
                                f"{description}"
                            ),
                            severity=Severity.HIGH if qty_value < 0 else Severity.MEDIUM,
                            target=target,
                            evidence=(
                                f"Quantity: {qty_value}\n"
                                f"Status: {resp.status_code}\n"
                                f"Body: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Validate quantities server-side: reject negative, "
                                "zero, fractional (if not supported), and enforce "
                                "reasonable upper bounds."
                            ),
                            cwe=20,
                            tags=["payment", "quantity-abuse", "waaaghlogic"],
                        ))
                        break  # One proof per step

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Step skipping
    # ----------------------------------------------------------

    async def _test_step_skipping(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test if checkout steps can be skipped."""
        findings: List[Finding] = []
        if not self._client or len(workflow.steps) < 2:
            return findings

        # Try jumping directly to the last step(s)
        for i in range(1, len(workflow.steps)):
            step = workflow.steps[i]

            try:
                resp = await self._client.request(
                    step.method, step.url,
                    json_body=step.body,
                    headers=step.headers,
                )

                if resp.status_code in (200, 201, 202):
                    text = resp.text.lower()
                    rejection_keywords = [
                        "cart is empty", "no items", "invalid session",
                        "step required", "must complete", "order not found",
                    ]
                    if not any(kw in text for kw in rejection_keywords):
                        skipped_steps = [s.name for s in workflow.steps[:i]]
                        findings.append(Finding(
                            title=f"Checkout step skipping: jumped to '{step.name}'",
                            description=(
                                f"Workflow '{workflow.name}': directly accessed "
                                f"step '{step.name}' without completing: "
                                f"{', '.join(skipped_steps)}. Server returned "
                                f"HTTP {resp.status_code} without rejection."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Skipped steps: {', '.join(skipped_steps)}\n"
                                f"Direct URL: {step.url}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Enforce server-side workflow state — each step must "
                                "validate that all previous steps were completed. "
                                "Use server-side session state, not client tokens."
                            ),
                            cwe=841,
                            tags=["payment", "step-skipping", "workflow", "waaaghlogic"],
                        ))

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Coupon abuse
    # ----------------------------------------------------------

    async def _test_coupon_abuse(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test coupon code abuse: stacking, reuse, injection."""
        findings: List[Finding] = []
        if not self._client or not workflow.coupon_endpoint:
            return findings

        endpoint = workflow.coupon_endpoint

        # --- Code enumeration / guessing ---
        for payload in COUPON_ABUSE_PAYLOADS:
            try:
                resp = await self._client.request(
                    "POST", endpoint,
                    json_body={"code": payload["code"]},
                )

                if resp.status_code in (200, 201):
                    text = resp.text.lower()
                    if any(kw in text for kw in [
                        "discount", "applied", "success", "valid",
                        "amount", "savings", "off",
                    ]):
                        findings.append(Finding(
                            title=f"Coupon code accepted: {payload['description']}",
                            description=(
                                f"The coupon endpoint accepted: {payload['code']!r}. "
                                f"{payload['description']}."
                            ),
                            severity=(
                                Severity.HIGH
                                if payload["code"] in ("", "' OR 1=1--", "AAAA" * 64)
                                else Severity.MEDIUM
                            ),
                            target=target,
                            evidence=(
                                f"Code: {payload['code'][:50]}\n"
                                f"Status: {resp.status_code}\n"
                                f"Body: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Validate coupon codes against a whitelist. "
                                "Rate-limit coupon attempts. Sanitize input."
                            ),
                            cwe=20,
                            tags=["coupon", "abuse", "waaaghlogic"],
                        ))

            except Exception:
                continue

        # --- Double application (stacking) ---
        try:
            # Apply same code twice
            resp1 = await self._client.request(
                "POST", endpoint, json_body={"code": "TEST"},
            )
            resp2 = await self._client.request(
                "POST", endpoint, json_body={"code": "TEST"},
            )

            if resp1.status_code == 200 and resp2.status_code == 200:
                text2 = resp2.text.lower()
                if "applied" in text2 or "discount" in text2:
                    if "already" not in text2 and "duplicate" not in text2:
                        findings.append(Finding(
                            title="Coupon stacking allowed (double application)",
                            description=(
                                "The same coupon code was accepted twice, with no "
                                "duplicate detection. This allows stacking discounts."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=f"Both applications returned 200 with 'applied'/'discount'",
                            remediation=(
                                "Track applied coupons per cart/session. Reject "
                                "duplicate applications. Enforce per-user usage limits."
                            ),
                            cwe=799,
                            tags=["coupon", "stacking", "waaaghlogic"],
                        ))
        except Exception:
            pass

        return findings

    # ----------------------------------------------------------
    # Gift card abuse
    # ----------------------------------------------------------

    async def _test_gift_card_abuse(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test gift card balance manipulation."""
        findings: List[Finding] = []
        if not self._client or not workflow.gift_card_endpoint:
            return findings

        endpoint = workflow.gift_card_endpoint

        # Negative amount application
        negative_payloads = [
            {"card_number": "TEST123", "amount": -100.00},
            {"card_number": "TEST123", "amount": -0.01},
            {"code": "GIFT123", "amount": -50},
        ]

        for payload in negative_payloads:
            try:
                resp = await self._client.request(
                    "POST", endpoint, json_body=payload,
                )

                if resp.status_code in (200, 201):
                    text = resp.text.lower()
                    if "error" not in text and "invalid" not in text:
                        findings.append(Finding(
                            title="Gift card negative amount accepted",
                            description=(
                                "A negative amount was applied via the gift card "
                                "endpoint. This could add credit instead of deducting, "
                                "or create a balance overflow."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Payload: {json.dumps(payload)}\n"
                                f"Status: {resp.status_code}\n"
                                f"Body: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Validate gift card amounts are positive. "
                                "Enforce balance limits and audit transactions."
                            ),
                            cwe=20,
                            tags=["gift-card", "negative-amount", "waaaghlogic"],
                        ))
                        break

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Negative total
    # ----------------------------------------------------------

    async def _test_negative_total(
        self, workflow: PaymentWorkflow, target: Target,
    ) -> List[Finding]:
        """Test if the order total can become negative (triggering refund)."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        for step in workflow.steps:
            if not step.body or not step.price_field:
                continue

            body = copy.deepcopy(step.body)
            self._set_nested(body, step.price_field, -100.00)

            # Also try adding a large discount
            body["discount"] = 99999.99
            body["tax"] = -10.00
            body["shipping"] = -5.00

            try:
                resp = await self._client.request(
                    step.method, step.url,
                    json_body=body,
                    headers=step.headers,
                )

                if resp.status_code in (200, 201):
                    try:
                        resp_body = json.loads(resp.text)
                        total = self._get_nested(resp_body, "total")
                        if total is not None and float(total) < 0:
                            findings.append(Finding(
                                title="Negative order total achieved",
                                description=(
                                    "The order total became negative, which could "
                                    "trigger a refund to the customer's payment method. "
                                    f"Total: {total}"
                                ),
                                severity=Severity.CRITICAL,
                                target=target,
                                evidence=(
                                    f"Manipulated body: {json.dumps(body)[:300]}\n"
                                    f"Response total: {total}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Enforce that order totals never go below zero. "
                                    "Calculate totals server-side from product catalog prices."
                                ),
                                cwe=472,
                                tags=["payment", "negative-total", "waaaghlogic"],
                            ))
                    except (json.JSONDecodeError, ValueError):
                        pass

            except Exception:
                continue

        return findings

    # ----------------------------------------------------------
    # Generic payment parameter tampering
    # ----------------------------------------------------------

    async def _test_payment_parameter_tampering(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test common payment parameter injection patterns."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        # Common checkout/payment endpoints to probe
        payment_endpoints = [
            f"{url}/checkout",
            f"{url}/api/checkout",
            f"{url}/payment",
            f"{url}/api/payment",
            f"{url}/api/orders",
        ]

        tampered_bodies = [
            {
                "name": "Zero price override",
                "body": {"total": 0, "amount": 0, "price": 0},
            },
            {
                "name": "Currency mismatch",
                "body": {"currency": "XAF", "amount": 100},
                # CFA Franc — much lower value than USD/EUR
            },
            {
                "name": "Free shipping override",
                "body": {"shipping": 0, "shipping_cost": 0, "delivery_fee": 0},
            },
            {
                "name": "Tax removal",
                "body": {"tax": 0, "vat": 0, "tax_exempt": True},
            },
        ]

        for endpoint in payment_endpoints:
            for tamper in tampered_bodies:
                try:
                    resp = await self._client.request(
                        "POST", endpoint,
                        json_body=tamper["body"],
                    )

                    if resp.status_code in (200, 201, 202):
                        text = resp.text.lower()
                        if "error" not in text and "invalid" not in text:
                            findings.append(Finding(
                                title=f"Payment parameter accepted: {tamper['name']}",
                                description=(
                                    f"The server accepted tampered payment parameters "
                                    f"({tamper['name']}) at {endpoint}."
                                ),
                                severity=Severity.MEDIUM,
                                target=target,
                                evidence=(
                                    f"Endpoint: {endpoint}\n"
                                    f"Body: {json.dumps(tamper['body'])}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Ignore client-supplied pricing, tax, shipping, "
                                    "and currency fields. Calculate all financial "
                                    "values server-side."
                                ),
                                cwe=472,
                                tags=["payment", "tampering", "waaaghlogic"],
                            ))
                            break  # One hit per endpoint

                except Exception:
                    continue

        return findings

    # ----------------------------------------------------------
    # Utility
    # ----------------------------------------------------------

    @staticmethod
    def _set_nested(data: Dict[str, Any], path: str, value: Any) -> None:
        """Set a value in a nested dict by dot-separated path."""
        keys = path.split(".")
        d = data
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value

    @staticmethod
    def _get_nested(data: Dict[str, Any], path: str) -> Any:
        """Get a value from a nested dict by dot-separated path."""
        keys = path.split(".")
        d = data
        for key in keys:
            if isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return None
        return d
