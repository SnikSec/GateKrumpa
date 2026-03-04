"""
OpenKrump — main module entry-point.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import BaseModule, Finding, ScanContext, Target
from krumpa.core.http_client import HttpClient
from krumpa.openkrump.parser import SpecParser, ParsedEndpoint
from krumpa.openkrump.validator import SchemaValidator, ValidationIssue
from krumpa.openkrump.bola_generator import BolaGenerator
from krumpa.openkrump.schema_validator import ResponseSchemaValidator
from krumpa.openkrump.spec_mass_assignment import SpecMassAssignmentChecker
from krumpa.openkrump.graphql_analyzer import GraphqlAnalyzer
from krumpa.openkrump.excessive_data import ExcessiveDataDetector
from krumpa.openkrump.spec_discovery import SpecDiscovery
from krumpa.openkrump.security_scheme_enforcer import SecuritySchemeEnforcer
from krumpa.openkrump.param_constraint_tester import ParamConstraintTester
from krumpa.openkrump.spec_diff import SpecDiffChecker
from krumpa.openkrump.grpc_protobuf import GrpcProtobufAnalyzer
from krumpa.openkrump.example_tester import ExampleTester
from krumpa.openkrump.api_versioning import ApiVersioningDetector
from krumpa.openkrump.webhook_security import WebhookSecurityAnalyzer
from krumpa.openkrump.validation_gaps import ValidationGapDetector

logger = logging.getLogger("krumpa.openkrump")


class OpenKrumpModule(BaseModule):
    """API-first testing — spec parsing, schema validation, security check."""

    name = "OpenKrump"
    description = "API-First Testing — OpenAPI spec parsing, schema validation, security checks"
    dependencies: List[str] = []  # independent discovery — can run parallel with SneakyGits

    def __init__(
        self,
        *,
        spec: Optional[Dict[str, Any]] = None,
        spec_url: Optional[str] = None,
        base_url: Optional[str] = None,
        http_client: Optional[HttpClient] = None,
        strict: bool = False,
    ) -> None:
        super().__init__()
        self._spec = spec
        self._spec_url = spec_url
        self._parser = SpecParser(base_url=base_url)
        self._validator = SchemaValidator(strict=strict)
        self._bola_generator = BolaGenerator()
        self._resp_validator = ResponseSchemaValidator(strict=strict)
        self._spec_mass_assign = SpecMassAssignmentChecker()
        self._graphql = GraphqlAnalyzer(http_client=http_client)
        self._excessive_data = ExcessiveDataDetector(http_client=http_client)
        self._spec_discovery = SpecDiscovery(http_client=http_client)
        self._sec_enforcer = SecuritySchemeEnforcer(http_client=http_client)
        self._param_tester = ParamConstraintTester(http_client=http_client)
        self._spec_diff = SpecDiffChecker(http_client=http_client)
        self._grpc = GrpcProtobufAnalyzer()
        self._example_tester = ExampleTester()
        self._api_versioning = ApiVersioningDetector()
        self._webhook_security = WebhookSecurityAnalyzer()
        self._validation_gaps = ValidationGapDetector()
        self._client = http_client
        self._explicit_client = http_client is not None
        self._owns_client = http_client is None
        self.endpoints: List[ParsedEndpoint] = []

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client if no explicit client was provided."""
        if ctx.http_client and not self._explicit_client:
            self._client = ctx.http_client
            self._owns_client = False
            self._spec_mass_assign._http_client = ctx.http_client
            self._graphql._client = ctx.http_client
            self._graphql._owns_client = False
            self._excessive_data._client = ctx.http_client
            self._excessive_data._owns_client = False
            self._spec_discovery._client = ctx.http_client
            self._spec_discovery._owns_client = False
            self._sec_enforcer._client = ctx.http_client
            self._sec_enforcer._owns_client = False
            self._param_tester._client = ctx.http_client
            self._param_tester._owns_client = False
            self._spec_diff._client = ctx.http_client
            self._spec_diff._owns_client = False
            self._grpc._client = ctx.http_client
            self._grpc._owns_client = False
            self._example_tester._client = ctx.http_client
            self._example_tester._owns_client = False
            self._api_versioning._client = ctx.http_client
            self._api_versioning._owns_client = False
            self._webhook_security._client = ctx.http_client
            self._webhook_security._owns_client = False
            self._validation_gaps._client = ctx.http_client
            self._validation_gaps._owns_client = False

    # ------------------------------------------------------------------
    # Module lifecycle
    # ------------------------------------------------------------------

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Auto-discover API specs if no spec was provided
        spec = await self._obtain_spec()
        if not spec and ctx.targets:
            base = ctx.targets[0].url.rstrip("/")
            disc_findings = await self._spec_discovery.discover(base)
            if disc_findings:
                logger.info("Auto-discovered %d API spec(s)", len(disc_findings))
                findings.extend(disc_findings)
                # Try to fetch + parse the first discovered spec as our OpenAPI spec
                for df in disc_findings:
                    if df.target and "openapi" in (df.evidence or "").lower():
                        spec = await self._try_fetch_spec(df.target.url)
                        if spec:
                            logger.info("Using auto-discovered spec from %s", df.target.url)
                            break
        else:
            spec = await self._obtain_spec()
        if not spec:
            logger.warning("OpenKrump: no spec available, skipping")
            return findings

        # 2. Parse endpoints
        self.endpoints = self._parser.parse(spec)
        logger.info("Parsed %d endpoints from spec", len(self.endpoints))

        # 3. Register endpoints as targets in context
        for ep in self.endpoints:
            url = self._parser.resolve_url(spec, ep.path)
            target = Target(
                url=url,
                method=ep.method,
                metadata={
                    "openapi_operation_id": ep.operation_id,
                    "openapi_tags": ep.tags,
                },
            )
            ctx.add_target(target)

        # 4. Security definition checks
        for ep in self.endpoints:
            url = self._parser.resolve_url(spec, ep.path)
            target = Target(url=url, method=ep.method)
            sec_issues = self._validator.check_security(ep)
            dep_issues = self._validator.check_deprecated(ep)
            all_issues = sec_issues + dep_issues
            if all_issues:
                findings.extend(self._validator.issues_to_findings(all_issues, target))

        # 5. Live schema validation (send requests and validate responses)
        client = self._client or HttpClient(timeout=10.0, retries=0)
        owns_temp_client = self._owns_client and client is not self._client
        try:
            for ep in self.endpoints:
                url = self._parser.resolve_url(spec, ep.path)
                target = Target(url=url, method=ep.method)
                try:
                    resp = await client.request(ep.method, url)
                    body = self._try_parse_json(resp.text)
                    if body is not None:
                        issues = self._validator.validate_response(
                            ep, resp.status_code, body,
                        )
                        if issues:
                            findings.extend(
                                self._validator.issues_to_findings(issues, target)
                            )
                except (httpx.HTTPError, OSError) as exc:
                    logger.debug("Error probing %s %s: %s", ep.method, url, exc)

            # 6. BOLA / IDOR analysis
            bola_findings = self._bola_generator.analyse_endpoints(self.endpoints)
            findings.extend(bola_findings)

            # 7. Full response schema validation
            for ep in self.endpoints:
                url = self._parser.resolve_url(spec, ep.path)
                target = Target(url=url, method=ep.method)
                for status_code, resp_schema in (ep.response_schemas or {}).items():
                    schema_def = resp_schema.get("schema") or resp_schema.get("content", {}).get("application/json", {}).get("schema", {})
                    if schema_def:
                        try:
                            resp = await client.request(ep.method, url)
                            body = self._try_parse_json(resp.text)
                            if body is not None:
                                resp_findings = self._resp_validator.validate(schema_def, body, target)
                                findings.extend(resp_findings)
                        except (httpx.HTTPError, OSError) as exc:
                            logger.debug("Schema validation error for %s %s: %s", ep.method, url, exc)
                        break  # only test one status code per endpoint

            # 8. Spec-based mass assignment detection
            spec_readonly = self._spec_mass_assign.extract_from_spec(spec)
            if spec_readonly:
                for schema_name, fields in spec_readonly.items():
                    for ep in self.endpoints:
                        if ep.method.upper() in ("POST", "PUT", "PATCH"):
                            url = self._parser.resolve_url(spec, ep.path)
                            target = Target(url=url, method=ep.method)
                            for field_name, source in fields.items():
                                result = await self._spec_mass_assign.test_field(target, field_name, source)
                                if result and result.was_accepted:
                                    from krumpa.core import Severity
                                    findings.append(Finding(
                                        title=f"Mass assignment: writable read-only field '{field_name}'",
                                        description=(
                                            f"Field '{field_name}' (marked {source} in schema '{schema_name}') "
                                            f"was accepted by {ep.method} {url}"
                                        ),
                                        severity=Severity.HIGH if source == "admin-field" else Severity.MEDIUM,
                                        target=target,
                                        evidence=f"schema={schema_name}, field={field_name}, source={source}",
                                        remediation="Reject writes to read-only fields. Use DTOs or allowlists.",
                                        cwe=915,
                                        tags=["mass-assignment", "api", "spec"],
                                    ))
                            break  # one endpoint per schema is enough

            # 9. GraphQL analysis — probe targets for GraphQL endpoints
            graphql_targets = [
                t for t in ctx.targets
                if any(kw in t.url.lower() for kw in ("/graphql", "/gql", "/query"))
            ]
            for gt in graphql_targets:
                gql_findings = await self._graphql.analyze(gt)
                findings.extend(gql_findings)

            # 10. Excessive data exposure — check live responses for PII / sensitive fields
            for ep in self.endpoints:
                url = self._parser.resolve_url(spec, ep.path)
                target = Target(url=url, method=ep.method)
                try:
                    resp = await client.request(ep.method, url)
                    body = self._try_parse_json(resp.text)
                    if body is not None and isinstance(body, dict):
                        expected = set()
                        for _status, rs in (ep.response_schemas or {}).items():
                            schema_def = (
                                rs.get("schema")
                                or rs.get("content", {}).get("application/json", {}).get("schema", {})
                            )
                            if schema_def:
                                expected = self._excessive_data.extract_expected_fields(schema_def)
                                break
                        ed_findings = self._excessive_data.check_response_fields(
                            body, expected_fields=expected or None, target=target,
                        )
                        findings.extend(ed_findings)
                except (httpx.HTTPError, OSError) as exc:
                    logger.debug("Excessive data check error for %s %s: %s", ep.method, url, exc)

            # 11. Security scheme enforcement — unauthenticated requests → verify 401/403
            base = self._parser.resolve_url(spec, "")
            sec_findings = await self._sec_enforcer.enforce(spec, self.endpoints, base)
            findings.extend(sec_findings)

            # 12. Parameter constraint testing — negative tests from spec constraints
            param_findings = await self._param_tester.test_endpoints(self.endpoints, base)
            findings.extend(param_findings)

            # 13. Spec diff / shadow API detection — deployed vs. spec comparison
            diff_findings = await self._spec_diff.diff(spec, self.endpoints, base)
            findings.extend(diff_findings)

            # 14. gRPC / Protobuf analysis — reflection, unauth access, transport
            for target in ctx.targets:
                grpc_findings = await self._grpc.analyze(target)
                findings.extend(grpc_findings)

            # 15. Example-based testing — execute spec examples and verify
            first_target = Target(url=base, method="GET") if ctx.targets else None
            if first_target:
                example_findings = await self._example_tester.analyze(first_target, spec)
                findings.extend(example_findings)

            # 16. API versioning — enumerate and check deprecated versions
            for target in ctx.targets:
                ver_findings = await self._api_versioning.analyze(target)
                findings.extend(ver_findings)

            # 17. Webhook security — SSRF, signature bypass, replay attacks
            for target in ctx.targets:
                webhook_findings = await self._webhook_security.analyze(target)
                findings.extend(webhook_findings)

            # 18. Validation gap detection — negative tests from spec constraints
            if first_target:
                gap_findings = await self._validation_gaps.analyze(first_target, spec)
                findings.extend(gap_findings)

        finally:
            if owns_temp_client:
                await client.close()

        for f in findings:
            self.add_finding(f)

        logger.info("OpenKrump complete — %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Spec retrieval
    # ------------------------------------------------------------------

    async def _obtain_spec(self) -> Optional[Dict[str, Any]]:
        """Return the spec dict, fetching from URL if needed."""
        if self._spec:
            return self._spec

        if self._spec_url:
            return await self._try_fetch_spec(self._spec_url)

        return None

    async def _try_fetch_spec(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse a JSON spec from *url*."""
        client = self._client or HttpClient(timeout=10.0, retries=0)
        try:
            resp = await client.request("GET", url)
            spec = json.loads(resp.text)
            if isinstance(spec, dict):
                self._spec = spec
                return spec
        except (httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to fetch spec from %s: %s", url, exc)
        finally:
            if self._owns_client and client is not self._client:
                await client.close()
        return None

    @staticmethod
    def _try_parse_json(text: str) -> Optional[Any]:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
