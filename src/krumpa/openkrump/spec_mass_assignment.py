"""
OpenKrump — Mass assignment detection from OpenAPI spec.

Derives read-only fields from the spec (readOnly, x-read-only, computed fields)
and attempts to overwrite them via API requests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.spec_mass_assignment")


# Fields commonly marked readOnly or inferred as dangerous to overwrite
_INFERRED_READONLY: Set[str] = {
    "id", "created_at", "createdAt", "updated_at", "updatedAt",
    "created_by", "createdBy", "modified_by", "modifiedBy",
    "uuid", "href", "self", "links", "_links",
}

_ADMIN_FIELDS: Set[str] = {
    "role", "roles", "is_admin", "isAdmin", "is_superuser",
    "isSuperuser", "permissions", "permission_level",
    "is_staff", "isStaff", "admin", "privilege",
}


@dataclass
class SpecMassAssignmentResult:
    """Result of attempting mass assignment on a single field."""
    field_name: str
    target: Target
    source: str  # "readOnly", "x-read-only", "inferred", "admin-field"
    was_accepted: bool  # True if the server accepted the write
    original_value: Any = None
    sent_value: Any = None
    response_value: Any = None


class SpecMassAssignmentChecker:
    """
    Detect mass assignment vulnerabilities by extracting read-only field
    metadata from an OpenAPI spec and testing if those fields can be
    overwritten via the API.
    """

    def __init__(
        self,
        http_client: Any = None,
        *,
        check_inferred: bool = True,
        check_admin_fields: bool = True,
    ) -> None:
        self._http_client = http_client
        self._owns_client = False
        self._check_inferred = check_inferred
        self._check_admin_fields = check_admin_fields

    # ------------------------------------------------------------------
    # Spec analysis (offline)
    # ------------------------------------------------------------------

    def extract_readonly_fields(
        self, schema: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Extract read-only fields from a JSON Schema object definition.

        Returns {field_name: source} where source describes why it's read-only.
        """
        readonly: Dict[str, str] = {}
        props = schema.get("properties", {})

        for name, prop_schema in props.items():
            if prop_schema.get("readOnly"):
                readonly[name] = "readOnly"
            elif prop_schema.get("x-read-only"):
                readonly[name] = "x-read-only"
            elif self._check_inferred and name.lower() in {f.lower() for f in _INFERRED_READONLY}:
                readonly[name] = "inferred"

        if self._check_admin_fields:
            for name in props:
                if name not in readonly and name.lower() in {f.lower() for f in _ADMIN_FIELDS}:
                    readonly[name] = "admin-field"

        return readonly

    def extract_from_spec(
        self, spec: Dict[str, Any],
    ) -> Dict[str, Dict[str, str]]:
        """
        Scan an entire OpenAPI spec for read-only fields.

        Returns {schema_name: {field_name: source}}.
        """
        results: Dict[str, Dict[str, str]] = {}

        schemas = spec.get("components", {}).get("schemas", {})
        # Swagger 2.0 fallback
        if not schemas:
            schemas = spec.get("definitions", {})

        for schema_name, schema_def in schemas.items():
            readonly = self.extract_readonly_fields(schema_def)
            if readonly:
                results[schema_name] = readonly

        return results

    # ------------------------------------------------------------------
    # Active testing
    # ------------------------------------------------------------------

    async def test_field(
        self,
        target: Target,
        field_name: str,
        source: str,
        *,
        test_value: Any = "__MASS_ASSIGN_TEST__",
    ) -> Optional[SpecMassAssignmentResult]:
        """
        Attempt to set a read-only field via the API and check if it
        was accepted.
        """
        if not self._http_client:
            return None

        # Build payload with just the read-only field
        payload = {field_name: test_value}

        try:
            resp = await self._http_client.request(
                method=target.method or "PUT",
                url=target.url,
                json=payload,
            )

            was_accepted = False
            response_value = None

            if resp.status_code < 400:
                # Check if the field appears in the response with our value
                try:
                    body = resp.json()
                    if isinstance(body, dict):
                        response_value = body.get(field_name)
                        if response_value == test_value:
                            was_accepted = True
                        elif field_name in body:
                            # Field present but with different value—might still
                            # be silently ignored, which is correct behavior.
                            was_accepted = False
                except Exception:
                    pass

                # If no JSON body but status is 2xx, it *might* have been accepted
                if resp.status_code < 300 and response_value is None:
                    was_accepted = False  # conservative: can't confirm

            return SpecMassAssignmentResult(
                field_name=field_name,
                target=target,
                source=source,
                was_accepted=was_accepted,
                sent_value=test_value,
                response_value=response_value,
            )

        except Exception as exc:
            logger.debug("Error testing field %s: %s", field_name, exc)
            return None

    async def test_target(
        self,
        target: Target,
        schema: Dict[str, Any],
    ) -> List[Finding]:
        """
        Test all read-only fields from a schema against a target endpoint.
        """
        readonly_fields = self.extract_readonly_fields(schema)
        findings: List[Finding] = []

        for field_name, source in readonly_fields.items():
            result = await self.test_field(target, field_name, source)
            if result and result.was_accepted:
                sev = (
                    Severity.HIGH if source == "admin-field"
                    else Severity.MEDIUM
                )
                findings.append(Finding(
                    title=f"Mass assignment: writable read-only field '{field_name}'",
                    description=(
                        f"The field '{field_name}' (marked as {source}) was "
                        f"accepted by {target.method or 'PUT'} {target.url}. "
                        f"Sent value: {result.sent_value}, "
                        f"Response value: {result.response_value}"
                    ),
                    severity=sev,
                    target=target,
                    evidence=f"field={field_name}, source={source}, accepted=True",
                    remediation=(
                        "Reject writes to read-only fields server-side. "
                        "Use DTOs or allowlists to control which fields are writable."
                    ),
                    cwe=915,
                    tags=["mass-assignment", "api", source],
                ))

        return findings

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def generate_test_plan(
        self, spec: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Generate a human-readable test plan from a spec without executing.
        """
        all_readonly = self.extract_from_spec(spec)
        plan: List[Dict[str, Any]] = []

        for schema_name, fields in all_readonly.items():
            for field_name, source in fields.items():
                plan.append({
                    "schema": schema_name,
                    "field": field_name,
                    "source": source,
                    "action": f"Attempt to set '{field_name}' via PUT/PATCH and verify rejection",
                })

        return plan
