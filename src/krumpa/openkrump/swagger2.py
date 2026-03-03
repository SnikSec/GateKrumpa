"""
OpenKrump — Swagger 2.0 native parser.

Converts Swagger 2.0 specs into internal Target objects, alongside existing
OpenAPI 3.x support.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krumpa.core import Target

logger = logging.getLogger("krumpa.openkrump.swagger2")


class Swagger2Parser:
    """Parse Swagger 2.0 specs into Targets + metadata."""

    def __init__(self) -> None:
        self._spec: Dict[str, Any] = {}
        self._base_url: str = ""

    def load(self, spec: Dict[str, Any], base_url: str = "") -> None:
        """Load a parsed Swagger 2.0 spec dict."""
        self._spec = spec
        swagger_version = spec.get("swagger", "")
        if not swagger_version.startswith("2"):
            raise ValueError(f"Expected Swagger 2.0 spec, got swagger={swagger_version!r}")

        # Determine base URL
        if base_url:
            self._base_url = base_url.rstrip("/")
        else:
            host = spec.get("host", "localhost")
            base_path = spec.get("basePath", "/")
            schemes = spec.get("schemes", ["https"])
            scheme = schemes[0] if schemes else "https"
            self._base_url = f"{scheme}://{host}{base_path}".rstrip("/")

    def extract_targets(self) -> List[Target]:
        """Extract all endpoints as Target objects."""
        targets: List[Target] = []

        paths = self._spec.get("paths", {})
        for path, path_item in paths.items():
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                if method not in path_item:
                    continue

                operation = path_item[method]
                url = f"{self._base_url}{path}"
                headers: Dict[str, str] = {}
                body: Optional[str] = None

                # Extract content type from consumes
                consumes = operation.get("consumes") or self._spec.get("consumes", [])
                if consumes:
                    headers["Content-Type"] = consumes[0]

                # Extract body from parameters
                for param in operation.get("parameters", []):
                    if param.get("in") == "body":
                        schema = param.get("schema", {})
                        body = self._build_example_body(schema)
                    elif param.get("in") == "header":
                        headers[param["name"]] = param.get("default", "test")

                targets.append(Target(
                    url=url,
                    method=method.upper(),
                    headers=headers,
                    body=body,
                ))

        return targets

    def get_security_definitions(self) -> Dict[str, Any]:
        """Return the securityDefinitions block."""
        return self._spec.get("securityDefinitions", {})

    def get_operation_security(self, path: str, method: str) -> List[Dict[str, List[str]]]:
        """Get security requirements for a specific operation."""
        paths = self._spec.get("paths", {})
        operation = paths.get(path, {}).get(method.lower(), {})
        return operation.get("security", self._spec.get("security", []))

    def get_definitions(self) -> Dict[str, Any]:
        """Return the definitions (model schemas) block."""
        return self._spec.get("definitions", {})

    def _build_example_body(self, schema: Dict[str, Any]) -> Optional[str]:
        """Build a minimal example JSON body from a Swagger schema."""
        if not schema:
            return None

        # Handle $ref
        if "$ref" in schema:
            ref_path = schema["$ref"]
            resolved = self._resolve_ref(ref_path)
            if resolved:
                return self._build_example_body(resolved)
            return None

        schema_type = schema.get("type", "object")
        if schema_type == "object":
            properties = schema.get("properties", {})
            example: Dict[str, Any] = {}
            for prop_name, prop_schema in properties.items():
                example[prop_name] = self._example_value(prop_schema)
            return json.dumps(example)
        elif schema_type == "array":
            items = schema.get("items", {})
            return json.dumps([self._example_value(items)])
        else:
            return json.dumps(self._example_value(schema))

    def _example_value(self, schema: Dict[str, Any]) -> Any:
        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"])
            if resolved:
                return self._build_example_dict(resolved)
            return {}

        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]

        schema_type = schema.get("type", "string")
        type_defaults: Dict[str, Any] = {
            "string": "test",
            "integer": 1,
            "number": 1.0,
            "boolean": True,
            "array": [],
            "object": {},
        }
        return type_defaults.get(schema_type, "test")

    def _build_example_dict(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        properties = schema.get("properties", {})
        result: Dict[str, Any] = {}
        for prop_name, prop_schema in properties.items():
            result[prop_name] = self._example_value(prop_schema)
        return result

    def _resolve_ref(self, ref: str) -> Optional[Dict[str, Any]]:
        """Resolve a JSON $ref pointer within the spec."""
        if not ref.startswith("#/"):
            return None
        parts = ref[2:].split("/")
        node: Any = self._spec
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node if isinstance(node, dict) else None
