"""
WaaaghLogic — multi-step workflow analyser.

Models application workflows as ordered sequences of HTTP requests and
tests them for business-logic flaws:

  - **Step skipping** — Can later steps be reached without completing
    earlier required steps?
  - **Parameter tampering** — Do mutated parameters (price, quantity,
    role, ID) produce unexpected success?
  - **State violations** — Does repeating or reordering steps break
    expected invariants?
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.waaaghlogic.flow")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class WorkflowStep(HttpClientMixin):
    """A single step in a multi-step business workflow."""
    name: str
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    expected_status: int = 200
    required: bool = True
    # Fields eligible for tampering tests
    tamper_fields: List[str] = field(default_factory=list)


@dataclass
class _StepResult(HttpClientMixin):
    """Outcome of executing a single workflow step."""
    step: WorkflowStep
    status_code: int
    body: str
    success: bool


# ------------------------------------------------------------------
# FlowAnalyzer
# ------------------------------------------------------------------

class FlowAnalyzer(HttpClientMixin):
    """
    Analyse multi-step workflows for business-logic vulnerabilities.

    Parameters
    ----------
    http_client:
        Optional shared :class:`HttpClient`.
    tamper_values:
        Mapping of field-type hints to mutation values.  Keys are
        substrings matched against field names (e.g. ``"price"``).
    """

    DEFAULT_TAMPER_VALUES: Dict[str, List[Any]] = {
        "price": [0, -1, 0.01, 99999999],
        "quantity": [0, -1, 99999999],
        "amount": [0, -1, 0.01, 99999999],
        "role": ["admin", "root", "superuser"],
        "id": [0, 1, "null", "undefined"],
        "discount": [100, 101, -1, 99999],
        "status": ["approved", "completed", "admin"],
    }

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        tamper_values: Optional[Dict[str, List[Any]]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self.tamper_values = tamper_values if tamper_values is not None else dict(self.DEFAULT_TAMPER_VALUES)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test_workflow(
        self,
        steps: List[WorkflowStep],
        target: Target,
    ) -> List[Finding]:
        """
        Run the full suite of business-logic tests against *steps*.
        """
        client = self._client or HttpClient(timeout=15.0, retries=1)
        try:
            findings: List[Finding] = []
            findings.extend(await self._test_step_skipping(client, steps, target))
            findings.extend(await self._test_parameter_tampering(client, steps, target))
            findings.extend(await self._test_replay(client, steps, target))
            return findings
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

    # ------------------------------------------------------------------
    # Step skipping
    # ------------------------------------------------------------------

    async def _test_step_skipping(
        self,
        client: HttpClient,
        steps: List[WorkflowStep],
        target: Target,
    ) -> List[Finding]:
        """Try accessing later steps without completing earlier required steps."""
        findings: List[Finding] = []

        for i, step in enumerate(steps):
            if i == 0:
                continue  # First step is always accessible

            result = await self._execute_step(client, step)
            if result.success:
                findings.append(Finding(
                    title=f"Step skipping: '{step.name}' accessible without prior steps",
                    description=(
                        f"Step '{step.name}' (#{i + 1}) at {step.url} returned "
                        f"status {result.status_code} without completing the preceding "
                        f"required steps. This may allow users to bypass workflow controls."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Direct request to {step.url} → {result.status_code}",
                    remediation=(
                        "Enforce server-side state checks ensuring prior steps are "
                        "completed before allowing access to subsequent steps."
                    ),
                    cwe=841,
                    tags=["business-logic", "step-skipping", "workflow"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Parameter tampering
    # ------------------------------------------------------------------

    async def _test_parameter_tampering(
        self,
        client: HttpClient,
        steps: List[WorkflowStep],
        target: Target,
    ) -> List[Finding]:
        """Mutate designated fields and check if the server accepts them."""
        findings: List[Finding] = []

        for step in steps:
            if not step.body or not step.tamper_fields:
                continue

            for field_name in step.tamper_fields:
                if field_name not in step.body:
                    continue

                mutations = self._get_mutations(field_name)
                original_value = step.body[field_name]

                for mutated_value in mutations:
                    mutated_body = copy.deepcopy(step.body)
                    mutated_body[field_name] = mutated_value

                    result = await self._execute_step(client, step, body_override=mutated_body)
                    if result.success:
                        findings.append(Finding(
                            title=f"Parameter tampering accepted: {field_name}={mutated_value!r}",
                            description=(
                                f"Step '{step.name}' accepted a tampered value for "
                                f"'{field_name}': {original_value!r} → {mutated_value!r}. "
                                f"The server returned status {result.status_code}."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"POST {step.url} with {field_name}={mutated_value!r} "
                                f"→ {result.status_code}"
                            ),
                            remediation=(
                                "Validate and sanitise all business-critical parameters "
                                "server-side. Never trust client-supplied prices, quantities, "
                                "or role identifiers."
                            ),
                            cwe=472,
                            tags=["business-logic", "parameter-tampering"],
                        ))
                        break  # One finding per field is enough

        return findings

    # ------------------------------------------------------------------
    # Replay / duplicate submission
    # ------------------------------------------------------------------

    async def _test_replay(
        self,
        client: HttpClient,
        steps: List[WorkflowStep],
        target: Target,
    ) -> List[Finding]:
        """Submit the same state-changing request twice and see if both succeed."""
        findings: List[Finding] = []

        for step in steps:
            if step.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            r1 = await self._execute_step(client, step)
            r2 = await self._execute_step(client, step)

            if r1.success and r2.success:
                findings.append(Finding(
                    title=f"Replay accepted: '{step.name}' succeeded twice",
                    description=(
                        f"The state-changing step '{step.name}' ({step.method} {step.url}) "
                        f"succeeded on consecutive identical submissions "
                        f"(status {r1.status_code}, {r2.status_code}). "
                        "This may allow duplicate transactions."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Two {step.method} {step.url} → {r1.status_code}, {r2.status_code}",
                    remediation=(
                        "Implement idempotency keys, nonces, or server-side duplicate "
                        "detection for state-changing operations."
                    ),
                    cwe=841,
                    tags=["business-logic", "replay", "idempotency"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_mutations(self, field_name: str) -> List[Any]:
        """Return tamper values for a field based on name heuristics."""
        lower = field_name.lower()
        for key, values in self.tamper_values.items():
            if key in lower:
                return values
        # Fallback: generic boundary values
        return [0, -1, "", None, "true", "admin"]

    async def _execute_step(
        self,
        client: HttpClient,
        step: WorkflowStep,
        *,
        body_override: Optional[Dict[str, Any]] = None,
    ) -> _StepResult:
        """Execute a single step and return the result."""
        body = body_override if body_override is not None else step.body
        try:
            resp = await client.request(
                step.method,
                step.url,
                headers=step.headers or None,
                json_body=body,
            )
            success = resp.status_code == step.expected_status
            return _StepResult(
                step=step,
                status_code=resp.status_code,
                body=resp.text,
                success=success,
            )
        except (httpx.HTTPError, OSError):
            logger.debug("Step '%s' request failed", step.name)
            return _StepResult(step=step, status_code=0, body="", success=False)
