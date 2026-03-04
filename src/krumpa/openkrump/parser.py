"""
OpenKrump — OpenAPI / Swagger specification parser.

Parses OpenAPI 3.x and Swagger 2.0 specs (as Python dicts) and produces
a list of :class:`ParsedEndpoint` objects suitable for automated testing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("krumpa.openkrump.parser")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class ParsedEndpoint:
    """An API endpoint extracted from an OpenAPI spec."""
    path: str
    method: str                                  # GET, POST, …
    operation_id: Optional[str] = None
    summary: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    security: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False

    @property
    def full_id(self) -> str:
        return f"{self.method.upper()} {self.path}"


# ------------------------------------------------------------------
# SpecParser
# ------------------------------------------------------------------

class SpecParser:
    """
    Parse an OpenAPI/Swagger spec dict into :class:`ParsedEndpoint` objects.

    Parameters
    ----------
    base_url:
        Override the server URL from the spec. If *None* the first
        server entry is used (or ``http://localhost`` as fallback).
    """

    def __init__(self, *, base_url: Optional[str] = None) -> None:
        self._base_url_override = base_url

    def parse(self, spec: Dict[str, Any]) -> List[ParsedEndpoint]:
        """Parse a spec dict and return endpoints."""
        version = self._detect_version(spec)
        if version == 3:
            return self._parse_openapi3(spec)
        elif version == 2:
            return self._parse_swagger2(spec)
        else:
            logger.warning("Unknown spec version, attempting OpenAPI 3 parse")
            return self._parse_openapi3(spec)

    @property
    def base_url(self) -> str:
        return self._base_url_override or "http://localhost"

    def resolve_url(self, spec: Dict[str, Any], path: str) -> str:
        """Build a full URL from the spec servers + path."""
        if self._base_url_override:
            return self._base_url_override.rstrip("/") + path

        # OpenAPI 3
        servers = spec.get("servers", [])
        if servers:
            return servers[0].get("url", "http://localhost").rstrip("/") + path

        # Swagger 2
        host = spec.get("host", "localhost")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        return f"{schemes[0]}://{host}{base_path}{path}"

    # ------------------------------------------------------------------
    # OpenAPI 3.x
    # ------------------------------------------------------------------

    def _parse_openapi3(self, spec: Dict[str, Any]) -> List[ParsedEndpoint]:
        endpoints: List[ParsedEndpoint] = []
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                params = list(path_item.get("parameters", [])) + list(operation.get("parameters", []))
                rb_schema = self._extract_request_body_3(operation)
                resp_schemas = self._extract_responses_3(operation)
                security = operation.get("security", global_security)

                endpoints.append(ParsedEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary", ""),
                    parameters=params,
                    request_body_schema=rb_schema,
                    response_schemas=resp_schemas,
                    security=security,
                    tags=operation.get("tags", []),
                    deprecated=operation.get("deprecated", False),
                ))

        logger.info("Parsed %d endpoints from OpenAPI 3 spec", len(endpoints))
        return endpoints

    @staticmethod
    def _extract_request_body_3(operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rb = operation.get("requestBody", {})
        if not rb:
            return None
        content = rb.get("content", {})
        for media_type in ("application/json", "application/x-www-form-urlencoded"):
            if media_type in content:
                return content[media_type].get("schema")
        # Return first available
        for _mt, mt_obj in content.items():
            return mt_obj.get("schema")
        return None

    @staticmethod
    def _extract_responses_3(operation: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for status, resp_obj in operation.get("responses", {}).items():
            if not isinstance(resp_obj, dict):
                continue
            content = resp_obj.get("content", {})
            for _mt, mt_obj in content.items():
                schema = mt_obj.get("schema")
                if schema:
                    result[str(status)] = schema
                    break
        return result

    # ------------------------------------------------------------------
    # Swagger 2.0
    # ------------------------------------------------------------------

    def _parse_swagger2(self, spec: Dict[str, Any]) -> List[ParsedEndpoint]:
        endpoints: List[ParsedEndpoint] = []
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                params = list(path_item.get("parameters", [])) + list(operation.get("parameters", []))
                rb_schema = self._extract_request_body_2(params)
                resp_schemas = self._extract_responses_2(operation)
                security = operation.get("security", global_security)

                endpoints.append(ParsedEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary", ""),
                    parameters=[p for p in params if p.get("in") != "body"],
                    request_body_schema=rb_schema,
                    response_schemas=resp_schemas,
                    security=security,
                    tags=operation.get("tags", []),
                    deprecated=operation.get("deprecated", False),
                ))

        logger.info("Parsed %d endpoints from Swagger 2 spec", len(endpoints))
        return endpoints

    @staticmethod
    def _extract_request_body_2(params: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for p in params:
            if p.get("in") == "body":
                return p.get("schema")
        return None

    @staticmethod
    def _extract_responses_2(operation: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for status, resp_obj in operation.get("responses", {}).items():
            if not isinstance(resp_obj, dict):
                continue
            schema = resp_obj.get("schema")
            if schema:
                result[str(status)] = schema
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_version(spec: Dict[str, Any]) -> int:
        if "openapi" in spec:
            return 3
        if "swagger" in spec:
            return 2
        return 0
