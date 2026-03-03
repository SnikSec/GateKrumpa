"""
WaaaghLogic — State machine modeling & illegal transition testing.

Test for illegal state transitions in workflow engines, order systems,
ticket systems, etc. via YAML-defined state machines.

CWE-841: Improper Enforcement of Behavioral Workflow
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.state_machine")


@dataclass
class StateTransition:
    """A single allowed state transition."""
    from_state: str
    to_state: str
    action: str = ""  # HTTP method + endpoint hint


@dataclass
class StateMachineDefinition:
    """
    A full state machine definition with named states and allowed
    transitions. Typically loaded from a YAML config.
    """
    name: str
    states: List[str]
    initial_state: str
    terminal_states: List[str]
    transitions: List[StateTransition]
    state_field: str = "status"

    @property
    def allowed_transitions(self) -> Dict[str, Set[str]]:
        """Build {from_state: {to_state, ...}} lookup."""
        result: Dict[str, Set[str]] = {}
        for t in self.transitions:
            result.setdefault(t.from_state, set()).add(t.to_state)
        return result

    def illegal_transitions(self) -> List[tuple[str, str]]:
        """
        Return all (from, to) pairs that are NOT in the allowed set,
        excluding self-transitions.
        """
        allowed = self.allowed_transitions
        illegal: List[tuple[str, str]] = []
        for s1 in self.states:
            for s2 in self.states:
                if s1 != s2 and s2 not in allowed.get(s1, set()):
                    illegal.append((s1, s2))
        return illegal


# ------------------------------------------------------------------
# Default state machine definitions
# ------------------------------------------------------------------

ORDER_STATE_MACHINE = StateMachineDefinition(
    name="Order Lifecycle",
    states=["pending", "confirmed", "processing", "shipped", "delivered", "cancelled", "refunded"],
    initial_state="pending",
    terminal_states=["delivered", "cancelled", "refunded"],
    transitions=[
        StateTransition("pending", "confirmed"),
        StateTransition("pending", "cancelled"),
        StateTransition("confirmed", "processing"),
        StateTransition("confirmed", "cancelled"),
        StateTransition("processing", "shipped"),
        StateTransition("processing", "cancelled"),
        StateTransition("shipped", "delivered"),
        StateTransition("delivered", "refunded"),
    ],
    state_field="status",
)

TICKET_STATE_MACHINE = StateMachineDefinition(
    name="Support Ticket",
    states=["open", "in_progress", "waiting_customer", "resolved", "closed", "reopened"],
    initial_state="open",
    terminal_states=["closed"],
    transitions=[
        StateTransition("open", "in_progress"),
        StateTransition("open", "closed"),
        StateTransition("in_progress", "waiting_customer"),
        StateTransition("in_progress", "resolved"),
        StateTransition("waiting_customer", "in_progress"),
        StateTransition("resolved", "closed"),
        StateTransition("resolved", "reopened"),
        StateTransition("reopened", "in_progress"),
        StateTransition("closed", "reopened"),
    ],
    state_field="status",
)

PAYMENT_STATE_MACHINE = StateMachineDefinition(
    name="Payment Lifecycle",
    states=["initiated", "authorized", "captured", "settled", "refunded", "failed", "voided"],
    initial_state="initiated",
    terminal_states=["settled", "refunded", "failed", "voided"],
    transitions=[
        StateTransition("initiated", "authorized"),
        StateTransition("initiated", "failed"),
        StateTransition("authorized", "captured"),
        StateTransition("authorized", "voided"),
        StateTransition("captured", "settled"),
        StateTransition("captured", "refunded"),
    ],
    state_field="status",
)

DEFAULT_MACHINES = [ORDER_STATE_MACHINE, TICKET_STATE_MACHINE, PAYMENT_STATE_MACHINE]


class StateMachineTester:
    """
    Test for illegal state transitions:
      1. Direct jumps (e.g., pending → delivered)
      2. Backward transitions (e.g., delivered → pending)
      3. Terminal state escape (e.g., cancelled → processing)
      4. Duplicate transitions (double-submit same transition)
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        state_machines: Optional[List[StateMachineDefinition]] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._machines = state_machines or DEFAULT_MACHINES

    async def test(self, target: Target) -> List[Finding]:
        """Run all state machine tests against the target."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            for machine in self._machines:
                f = await self._test_illegal_transitions(client, target, machine)
                findings.extend(f)

                f = await self._test_terminal_escapes(client, target, machine)
                findings.extend(f)

                f = await self._test_double_transition(client, target, machine)
                findings.extend(f)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    async def _test_illegal_transitions(
        self,
        client: HttpClient,
        target: Target,
        machine: StateMachineDefinition,
    ) -> List[Finding]:
        """Try all illegal state transitions and report accepted ones."""
        findings: List[Finding] = []
        illegal = machine.illegal_transitions()

        for from_state, to_state in illegal[:20]:  # cap at 20 to avoid flooding
            body = {machine.state_field: to_state}
            try:
                resp = await client.request(
                    "PATCH", target.url, json_body=body,
                    headers={"X-Current-State": from_state},
                )
                if resp.status_code in (200, 201, 202, 204):
                    text = resp.text.lower()
                    if to_state.lower() in text:
                        findings.append(Finding(
                            title=(
                                f"Illegal state transition accepted: "
                                f"{from_state}→{to_state} ({machine.name}) on {target.url}"
                            ),
                            description=(
                                f"The '{machine.name}' state machine allowed "
                                f"transition from '{from_state}' to '{to_state}', "
                                f"which is not a defined legal transition. "
                                f"This can lead to business logic bypass."
                            ),
                            severity=Severity.HIGH,
                            target=target,
                            evidence=(
                                f"Machine: {machine.name}\n"
                                f"Transition: {from_state} → {to_state}\n"
                                f"Field: {machine.state_field}\n"
                                f"Status: {resp.status_code}"
                            ),
                            remediation=(
                                "Enforce state machine transitions server-side. "
                                "Validate current state before accepting transitions. "
                                "Use a state machine library or database constraints."
                            ),
                            cwe=841,
                            tags=["state-machine", "illegal-transition", "waaaghlogic"],
                        ))
                        break  # one finding per machine is enough
            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    async def _test_terminal_escapes(
        self,
        client: HttpClient,
        target: Target,
        machine: StateMachineDefinition,
    ) -> List[Finding]:
        """Try escaping terminal states (e.g., cancelled → processing)."""
        findings: List[Finding] = []

        for terminal in machine.terminal_states:
            # Try transitioning to non-terminal states
            for state in machine.states:
                if state in machine.terminal_states or state == terminal:
                    continue
                # Skip if this is actually allowed
                if state in machine.allowed_transitions.get(terminal, set()):
                    continue

                body = {machine.state_field: state}
                try:
                    resp = await client.request(
                        "PATCH", target.url, json_body=body,
                        headers={"X-Current-State": terminal},
                    )
                    if resp.status_code in (200, 201, 202, 204):
                        text = resp.text.lower()
                        if state.lower() in text:
                            findings.append(Finding(
                                title=(
                                    f"Terminal state escape: {terminal}→{state} "
                                    f"({machine.name}) on {target.url}"
                                ),
                                description=(
                                    f"The '{machine.name}' state machine allowed "
                                    f"escaping terminal state '{terminal}' to '{state}'. "
                                    f"Terminal states should be irrevocable (e.g., "
                                    f"a cancelled order should not become processing)."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=(
                                    f"Machine: {machine.name}\n"
                                    f"Escape: {terminal} → {state}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Enforce terminal state finality. Reject any "
                                    "transition from a terminal state to an active state."
                                ),
                                cwe=841,
                                tags=["state-machine", "terminal-escape", "waaaghlogic"],
                            ))
                            return findings
                except (httpx.HTTPError, OSError, ValueError):
                    continue

        return findings

    async def _test_double_transition(
        self,
        client: HttpClient,
        target: Target,
        machine: StateMachineDefinition,
    ) -> List[Finding]:
        """Submit the same transition twice to detect idempotency issues."""
        findings: List[Finding] = []

        if not machine.transitions:
            return findings

        # Pick the first valid transition
        transition = machine.transitions[0]
        body = {machine.state_field: transition.to_state}

        statuses: List[int] = []
        try:
            for _ in range(2):
                resp = await client.request(
                    "PATCH", target.url, json_body=body,
                    headers={"X-Current-State": transition.from_state},
                )
                statuses.append(resp.status_code)

            # Both succeed — might indicate no idempotency protection
            if all(s in (200, 201, 202, 204) for s in statuses):
                findings.append(Finding(
                    title=(
                        f"Double state transition accepted ({machine.name}) on {target.url}"
                    ),
                    description=(
                        f"Submitting the same transition "
                        f"({transition.from_state}→{transition.to_state}) twice "
                        f"was accepted both times. This may indicate missing idempotency "
                        f"protection, leading to duplicate processing."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=(
                        f"Machine: {machine.name}\n"
                        f"Transition: {transition.from_state} → {transition.to_state}\n"
                        f"Responses: {statuses}"
                    ),
                    remediation=(
                        "Use optimistic locking or state version checks. "
                        "Return 409 Conflict for duplicate transitions."
                    ),
                    cwe=841,
                    tags=["state-machine", "double-transition", "idempotency", "waaaghlogic"],
                ))
        except (httpx.HTTPError, OSError, ValueError):
            pass

        return findings

    @classmethod
    def from_yaml_config(
        cls,
        config: Dict[str, Any],
        *,
        http_client: Optional[HttpClient] = None,
    ) -> "StateMachineTester":
        """
        Build a tester from YAML config:

            state_machines:
              - name: Order Lifecycle
                states: [pending, confirmed, shipped, delivered, cancelled]
                initial_state: pending
                terminal_states: [delivered, cancelled]
                state_field: status
                transitions:
                  - from: pending
                    to: confirmed
                  - from: confirmed
                    to: shipped
        """
        machines: List[StateMachineDefinition] = []
        for m in config.get("state_machines", []):
            transitions = [
                StateTransition(
                    from_state=t["from"],
                    to_state=t["to"],
                    action=t.get("action", ""),
                )
                for t in m.get("transitions", [])
            ]
            machines.append(StateMachineDefinition(
                name=m["name"],
                states=m["states"],
                initial_state=m["initial_state"],
                terminal_states=m.get("terminal_states", []),
                transitions=transitions,
                state_field=m.get("state_field", "status"),
            ))

        return cls(http_client=http_client, state_machines=machines)
