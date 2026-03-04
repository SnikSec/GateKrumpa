"""Example-based testing — spec examples as positive test cases.

Phase 4 item #59.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger("krumpa.openkrump.example_tester")


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class SpecExample:
    """An example extracted from an OpenAPI spec."""
    path: str
    method: str
    name: str = ""
    description: str = ""
    request_body: Optional[Dict[str, Any]] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_status: int = 200
    expected_content_type: str = ""
    expected_schema: Optional[Dict[str, Any]] = None
    source: str = ""  # where in the spec this came from


@dataclass
class ExampleTestResult:
    """Result from running one example test."""
    example: SpecExample
    actual_status: int = 0
    actual_content_type: str = ""
    passed: bool = False
    error: str = ""
    response_body: str = ""


class ExampleTester:
    """Run spec-defined examples as positive test cases.

    OpenAPI specs can include `example` / `examples` at multiple levels
    (parameters, request bodies, responses). This module extracts them
    and fires real requests to verify the server behaves as documented.

    Discrepancies between spec examples and actual behavior indicate
    either outdated documentation or implementation bugs.
    """

    def __init__(self) -> None:
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(
        self, target: Target, spec: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Extract and run all examples from the spec."""
        findings: List[Finding] = []

        if not spec:
            return findings

        examples = self._extract_examples(spec)
        if not examples:
            logger.info("No examples found in spec")
            return findings

        logger.info("Found %d examples to test", len(examples))

        for ex in examples:
            result = await self._run_example(ex, target)
            if not result.passed:
                findings.append(self._result_to_finding(result, target))

        return findings

    # ----------------------------------------------------------
    # Example extraction
    # ----------------------------------------------------------

    def _extract_examples(self, spec: Dict[str, Any]) -> List[SpecExample]:
        """Extract examples from an OpenAPI 3.x spec."""
        examples: List[SpecExample] = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ("get", "post", "put", "patch", "delete", "options", "head"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue

                # Extract parameter examples
                params = self._extract_parameter_examples(
                    operation.get("parameters", []),
                    path_item.get("parameters", []),
                )

                # Extract request body examples
                req_bodies = self._extract_request_body_examples(
                    operation.get("requestBody", {}),
                )

                # Extract expected responses
                responses = operation.get("responses", {})
                expected_status = self._infer_success_status(responses)
                expected_ct, expected_schema = self._infer_response_format(
                    responses, expected_status,
                )

                if req_bodies:
                    for i, body in enumerate(req_bodies):
                        examples.append(SpecExample(
                            path=path,
                            method=method.upper(),
                            name=f"{method.upper()} {path} (body example {i+1})",
                            request_body=body,
                            parameters=params,
                            expected_status=expected_status,
                            expected_content_type=expected_ct,
                            expected_schema=expected_schema,
                            source=f"paths.{path}.{method}.requestBody",
                        ))
                elif params:
                    examples.append(SpecExample(
                        path=path,
                        method=method.upper(),
                        name=f"{method.upper()} {path} (param examples)",
                        parameters=params,
                        expected_status=expected_status,
                        expected_content_type=expected_ct,
                        expected_schema=expected_schema,
                        source=f"paths.{path}.{method}.parameters",
                    ))

        return examples

    def _extract_parameter_examples(
        self, *param_lists: Any,
    ) -> Dict[str, Any]:
        """Extract example values from parameter definitions."""
        params: Dict[str, Any] = {}

        for param_list in param_lists:
            if not isinstance(param_list, list):
                continue
            for param in param_list:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                if not name:
                    continue

                # Direct example
                if "example" in param:
                    params[name] = param["example"]
                elif "examples" in param and isinstance(param["examples"], dict):
                    # Take first example
                    for _key, ex_obj in param["examples"].items():
                        if isinstance(ex_obj, dict) and "value" in ex_obj:
                            params[name] = ex_obj["value"]
                            break
                elif "schema" in param and isinstance(param["schema"], dict):
                    schema = param["schema"]
                    if "example" in schema:
                        params[name] = schema["example"]
                    elif "default" in schema:
                        params[name] = schema["default"]

        return params

    def _extract_request_body_examples(
        self, request_body: Any,
    ) -> List[Dict[str, Any]]:
        """Extract example request bodies."""
        bodies: List[Dict[str, Any]] = []

        if not isinstance(request_body, dict):
            return bodies

        content = request_body.get("content", {})
        for _ct, media_type in content.items():
            if not isinstance(media_type, dict):
                continue

            if "example" in media_type:
                if isinstance(media_type["example"], dict):
                    bodies.append(media_type["example"])

            if "examples" in media_type and isinstance(media_type["examples"], dict):
                for _name, ex_obj in media_type["examples"].items():
                    if isinstance(ex_obj, dict) and "value" in ex_obj:
                        val = ex_obj["value"]
                        if isinstance(val, dict):
                            bodies.append(val)

            # Schema-level example
            schema = media_type.get("schema", {})
            if isinstance(schema, dict) and "example" in schema:
                val = schema["example"]
                if isinstance(val, dict):
                    bodies.append(val)

        return bodies

    @staticmethod
    def _infer_success_status(responses: Any) -> int:
        """Infer the expected success status code."""
        if not isinstance(responses, dict):
            return 200

        for code in ("200", "201", "202", "204"):
            if code in responses:
                return int(code)

        # Check for 2xx pattern
        if "2XX" in responses or "2xx" in responses:
            return 200

        return 200

    @staticmethod
    def _infer_response_format(
        responses: Any, status: int,
    ) -> tuple[str, Optional[Dict[str, Any]]]:
        """Infer expected content type and schema from response definition."""
        if not isinstance(responses, dict):
            return "", None

        resp_def = responses.get(str(status), responses.get("default", {}))
        if not isinstance(resp_def, dict):
            return "", None

        content = resp_def.get("content", {})
        for ct, media_type in content.items():
            if isinstance(media_type, dict):
                schema = media_type.get("schema")
                return ct, schema if isinstance(schema, dict) else None

        return "", None

    # ----------------------------------------------------------
    # Example execution
    # ----------------------------------------------------------

    async def _run_example(
        self, example: SpecExample, target: Target,
    ) -> ExampleTestResult:
        """Execute a single example against the live API."""
        result = ExampleTestResult(example=example)

        if not self._client:
            result.error = "No HTTP client available"
            return result

        # Build the request URL
        url = self._build_url(example, target)

        # Build query params
        query_params: Dict[str, str] = {}
        path_params: Dict[str, str] = {}
        for name, value in example.parameters.items():
            # Heuristic: if the param name appears in the path template, it's a path param
            if f"{{{name}}}" in example.path:
                path_params[name] = str(value)
            else:
                query_params[name] = str(value)

        # Replace path parameters in URL
        final_url = url
        for name, val in path_params.items():
            final_url = final_url.replace(f"{{{name}}}", val)

        try:
            _kwargs: Dict[str, Any] = {}
            if query_params:
                # Append query string
                qs = "&".join(f"{k}={v}" for k, v in query_params.items())
                sep = "&" if "?" in final_url else "?"
                final_url = f"{final_url}{sep}{qs}"

            if example.request_body:
                resp = await self._client.request(
                    example.method, final_url,
                    json_body=example.request_body,
                )
            else:
                resp = await self._client.request(example.method, final_url)

            result.actual_status = resp.status_code
            result.actual_content_type = resp.headers.get("content-type", "")
            result.response_body = resp.text[:2000]

            # Validate
            result.passed = self._validate_response(example, result)

        except Exception as exc:
            result.error = str(exc)[:200]

        return result

    @staticmethod
    def _build_url(example: SpecExample, target: Target) -> str:
        """Build the full URL for an example."""
        return urljoin(target.url.rstrip("/") + "/", example.path.lstrip("/"))

    @staticmethod
    def _validate_response(
        example: SpecExample, result: ExampleTestResult,
    ) -> bool:
        """Check if the actual response matches expectations."""
        # Status code check
        if example.expected_status:
            status_class = example.expected_status // 100
            actual_class = result.actual_status // 100
            if actual_class != status_class:
                return False

        # Content type check (loose)
        if example.expected_content_type and result.actual_content_type:
            expected_base = example.expected_content_type.split(";")[0].strip()
            actual_base = result.actual_content_type.split(";")[0].strip()
            if expected_base != actual_base:
                return False

        return True

    # ----------------------------------------------------------
    # Finding generation
    # ----------------------------------------------------------

    def _result_to_finding(
        self, result: ExampleTestResult, target: Target,
    ) -> Finding:
        """Convert a failed example test to a Finding."""
        ex = result.example
        details: List[str] = []

        if result.error:
            details.append(f"Error: {result.error}")
        else:
            if ex.expected_status and result.actual_status:
                details.append(
                    f"Expected status: {ex.expected_status}, "
                    f"Got: {result.actual_status}"
                )
            if ex.expected_content_type and result.actual_content_type:
                details.append(
                    f"Expected CT: {ex.expected_content_type}, "
                    f"Got: {result.actual_content_type}"
                )
            if result.response_body:
                details.append(f"Response: {result.response_body[:300]}")

        return Finding(
            title=f"Spec example mismatch: {ex.name}",
            description=(
                f"The API's response for spec example '{ex.name}' does not "
                f"match the documented behavior. This indicates either outdated "
                f"documentation or an implementation bug."
            ),
            severity=Severity.LOW,
            target=target,
            evidence=(
                f"Source: {ex.source}\n"
                f"Method: {ex.method} {ex.path}\n"
                + "\n".join(details)
            ),
            remediation=(
                "Update the API spec examples to match actual behavior, "
                "or fix the API implementation to match the spec."
            ),
            cwe=684,
            tags=["api-spec", "example-test", "spec-mismatch", "openkrump"],
        )
