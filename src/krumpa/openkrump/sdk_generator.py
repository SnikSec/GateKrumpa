"""
GateKrumpa — Typed Python SDK generator from OpenAPI / Swagger specs.

Reads a parsed spec (via :class:`SpecParser`) and emits a self-contained
Python module that contains:

* A typed **client class** with one method per endpoint.
* Typed **dataclasses** for request/response models (from ``$ref`` schemas).
* Proper ``httpx``-based async implementation with auth helpers.

Usage::

    from krumpa.openkrump.parser import SpecParser
    from krumpa.openkrump.sdk_generator import generate_sdk

    spec = {...}   # parsed JSON/YAML
    parser = SpecParser(base_url="https://api.example.com")
    endpoints = parser.parse(spec)
    code = generate_sdk(spec, endpoints, parser.base_url)
    Path("my_client.py").write_text(code)
"""

from __future__ import annotations

import keyword
import logging
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from krumpa.openkrump.parser import ParsedEndpoint

logger = logging.getLogger("krumpa.openkrump.sdk_generator")


# ===================================================================
# Public API
# ===================================================================

def generate_sdk(
    spec: Dict[str, Any],
    endpoints: List[ParsedEndpoint],
    base_url: str = "http://localhost",
    *,
    class_name: str = "ApiClient",
    module_docstring: str | None = None,
) -> str:
    """Generate a typed Python SDK module from an OpenAPI spec.

    Parameters
    ----------
    spec:
        The raw OpenAPI/Swagger spec dict (used for schema resolution).
    endpoints:
        Parsed endpoints from :class:`SpecParser.parse`.
    base_url:
        Base URL for the generated client.
    class_name:
        Name of the generated client class.
    module_docstring:
        Top-level docstring for the generated module.

    Returns
    -------
    str
        Complete Python source code for the SDK module.
    """
    gen = _SdkGenerator(spec=spec, base_url=base_url, class_name=class_name)
    return gen.generate(endpoints, module_docstring=module_docstring)


# ===================================================================
# Schema → Python type mapping
# ===================================================================

_JSON_TYPE_MAP: Dict[str, str] = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
}

_FORMAT_OVERRIDES: Dict[str, str] = {
    "date-time": "str",
    "date": "str",
    "binary": "bytes",
    "byte": "str",
    "uuid": "str",
    "uri": "str",
    "email": "str",
    "int64": "int",
    "int32": "int",
    "float": "float",
    "double": "float",
}


def _safe_identifier(name: str) -> str:
    """Convert an arbitrary string to a valid Python identifier."""
    ident = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    ident = re.sub(r"^(\d)", r"_\1", ident)
    if keyword.iskeyword(ident) or ident in ("None", "True", "False"):
        ident += "_"
    return ident


def _snake_case(name: str) -> str:
    """Convert CamelCase / kebab-case / mixed to snake_case."""
    # Insert underscores before uppercase runs
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"[-.\s]+", "_", s)
    return _safe_identifier(s.lower())


def _pascal_case(name: str) -> str:
    """Convert arbitrary string to PascalCase."""
    # First insert separators at camelCase boundaries so we preserve them
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    parts = re.split(r"[-_.\s]+", s)
    return "".join(p.capitalize() for p in parts if p)


# ===================================================================
# Internal generator
# ===================================================================

@dataclass
class _ModelField:
    name: str
    python_type: str
    required: bool
    description: str = ""
    default: str | None = None


@dataclass
class _Model:
    class_name: str
    fields: List[_ModelField] = field(default_factory=list)
    docstring: str = ""


@dataclass
class _MethodParam:
    name: str
    python_type: str
    required: bool
    location: str  # path, query, header, body
    description: str = ""


@dataclass
class _Method:
    name: str
    http_method: str
    path: str
    summary: str
    params: List[_MethodParam] = field(default_factory=list)
    body_model: str | None = None
    body_type: str = "dict"
    return_type: str = "httpx.Response"
    deprecated: bool = False


class _SdkGenerator:
    """Stateful generator that collects models and methods."""

    def __init__(
        self,
        spec: Dict[str, Any],
        base_url: str,
        class_name: str,
    ) -> None:
        self._spec = spec
        self._base_url = base_url.rstrip("/")
        self._class_name = class_name
        self._models: Dict[str, _Model] = {}
        self._methods: List[_Method] = []
        self._seen_method_names: Set[str] = set()

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def generate(
        self,
        endpoints: List[ParsedEndpoint],
        *,
        module_docstring: str | None = None,
    ) -> str:
        # 1. Walk endpoints → build _Method + _Model objects
        for ep in endpoints:
            self._process_endpoint(ep)

        # 2. Assemble source
        parts: List[str] = []
        parts.append(self._render_header(module_docstring))
        parts.append(self._render_imports())
        for model in self._models.values():
            parts.append(self._render_model(model))
        parts.append(self._render_client_class())
        return "\n\n".join(parts) + "\n"

    # ------------------------------------------------------------------
    # Endpoint → Method + Models
    # ------------------------------------------------------------------

    def _process_endpoint(self, ep: ParsedEndpoint) -> None:
        method_name = self._method_name(ep)
        params: List[_MethodParam] = []

        # Path / query / header params
        for p in ep.parameters:
            param_name = _snake_case(p.get("name", "param"))
            param_type = self._schema_to_type(p.get("schema", p))
            params.append(_MethodParam(
                name=param_name,
                python_type=param_type,
                required=p.get("required", p.get("in") == "path"),
                location=p.get("in", "query"),
                description=p.get("description", ""),
            ))

        # Request body
        body_model: str | None = None
        body_type = "dict"
        if ep.request_body_schema:
            model_name = self._register_schema(
                ep.request_body_schema,
                hint=f"{method_name}_body",
            )
            if model_name:
                body_model = model_name
                body_type = model_name

        self._methods.append(_Method(
            name=method_name,
            http_method=ep.method,
            path=ep.path,
            summary=ep.summary,
            params=params,
            body_model=body_model,
            body_type=body_type,
            deprecated=ep.deprecated,
        ))

    def _method_name(self, ep: ParsedEndpoint) -> str:
        """Derive a unique snake_case method name."""
        if ep.operation_id:
            base = _snake_case(ep.operation_id)
        else:
            verb = ep.method.lower()
            path_parts = [p for p in ep.path.split("/") if p and not p.startswith("{")]
            base = _snake_case(f"{verb}_{'_'.join(path_parts)}" if path_parts else verb)

        name = base
        counter = 2
        while name in self._seen_method_names:
            name = f"{base}_{counter}"
            counter += 1
        self._seen_method_names.add(name)
        return name

    # ------------------------------------------------------------------
    # Schema → Model registration
    # ------------------------------------------------------------------

    def _register_schema(
        self,
        schema: Dict[str, Any],
        hint: str = "Model",
    ) -> str | None:
        """Register a JSON Schema as a dataclass model, return class name."""
        # Resolve $ref
        resolved = self._resolve_ref(schema) if "$ref" in schema else schema
        if not resolved:
            return None

        # Determine class name
        ref_name = schema.get("$ref", "").rsplit("/", 1)[-1] if "$ref" in schema else ""
        class_name = _pascal_case(ref_name) if ref_name else _pascal_case(hint)
        if not class_name:
            return None

        # Already registered
        if class_name in self._models:
            return class_name

        schema_type = resolved.get("type", "object")
        if schema_type != "object":
            return None

        properties = resolved.get("properties", {})
        required_set = set(resolved.get("required", []))
        fields_list: List[_ModelField] = []

        for prop_name, prop_schema in properties.items():
            py_type = self._schema_to_type(prop_schema)
            is_required = prop_name in required_set
            fields_list.append(_ModelField(
                name=_snake_case(prop_name),
                python_type=py_type if is_required else f"Optional[{py_type}]",
                required=is_required,
                description=prop_schema.get("description", ""),
            ))

        # Sort: required first, then optional
        fields_list.sort(key=lambda f: (not f.required, f.name))

        self._models[class_name] = _Model(
            class_name=class_name,
            fields=fields_list,
            docstring=resolved.get("description", ""),
        )

        # Recursively register nested object properties
        for prop_name, prop_schema in properties.items():
            nested = self._resolve_ref(prop_schema) if "$ref" in prop_schema else prop_schema
            if nested and nested.get("type") == "object" and nested.get("properties"):
                self._register_schema(prop_schema, hint=prop_name)

        return class_name

    def _schema_to_type(self, schema: Dict[str, Any]) -> str:
        """Convert a JSON Schema to a Python type annotation string."""
        if "$ref" in schema:
            ref_name = schema["$ref"].rsplit("/", 1)[-1]
            model_name = _pascal_case(ref_name)
            # Register if not yet seen
            self._register_schema(schema, hint=ref_name)
            return model_name

        fmt = schema.get("format", "")
        if fmt in _FORMAT_OVERRIDES:
            return _FORMAT_OVERRIDES[fmt]

        schema_type = schema.get("type", "Any")

        if schema_type == "array":
            items = schema.get("items", {})
            item_type = self._schema_to_type(items) if items else "Any"
            return f"List[{item_type}]"

        if schema_type == "object":
            # Check for additionalProperties (map type)
            add_props = schema.get("additionalProperties")
            if isinstance(add_props, dict):
                val_type = self._schema_to_type(add_props)
                return f"Dict[str, {val_type}]"
            return "Dict[str, Any]"

        return _JSON_TYPE_MAP.get(schema_type, "Any")

    def _resolve_ref(self, schema: Dict[str, Any]) -> Dict[str, Any] | None:
        """Resolve a $ref pointer within the spec."""
        ref = schema.get("$ref", "")
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

    # ------------------------------------------------------------------
    # Code rendering
    # ------------------------------------------------------------------

    def _render_header(self, docstring: str | None) -> str:
        title = self._spec.get("info", {}).get("title", "API")
        version = self._spec.get("info", {}).get("version", "")
        default_doc = f'"""Auto-generated Python SDK for {title} {version}.\n\nGenerated by GateKrumpa SDK generator.\n"""'
        doc = f'"""{docstring}"""' if docstring else default_doc
        return f"# Auto-generated by GateKrumpa SDK Generator\n# Do not edit manually.\n\n{doc}"

    @staticmethod
    def _render_imports() -> str:
        return textwrap.dedent("""\
            from __future__ import annotations

            from dataclasses import dataclass, field
            from typing import Any, Dict, List, Optional

            import httpx""")

    @staticmethod
    def _render_model(model: _Model) -> str:
        lines: List[str] = []
        lines.append("@dataclass")
        lines.append(f"class {model.class_name}:")
        if model.docstring:
            lines.append(f'    """{model.docstring}"""')
        if not model.fields:
            lines.append("    pass")
        else:
            for f in model.fields:
                default = ""
                if not f.required:
                    default = " = None"
                comment = f"  # {f.description}" if f.description else ""
                lines.append(f"    {f.name}: {f.python_type}{default}{comment}")

            # to_dict helper
            lines.append("")
            lines.append("    def to_dict(self) -> Dict[str, Any]:")
            lines.append("        d: Dict[str, Any] = {}")
            for f in model.fields:
                if f.required:
                    lines.append(f'        d["{f.name}"] = self.{f.name}')
                else:
                    lines.append(f"        if self.{f.name} is not None:")
                    lines.append(f'            d["{f.name}"] = self.{f.name}')
            lines.append("        return d")

        return "\n".join(lines)

    def _render_client_class(self) -> str:
        lines: List[str] = []
        lines.append(f"class {self._class_name}:")
        title = self._spec.get("info", {}).get("title", "API")
        lines.append(f'    """Typed HTTP client for {title}."""')
        lines.append("")
        lines.append("    def __init__(")
        lines.append("        self,")
        lines.append(f'        base_url: str = "{self._base_url}",')
        lines.append("        *,")
        lines.append("        headers: Dict[str, str] | None = None,")
        lines.append("        auth_token: str | None = None,")
        lines.append("        timeout: float = 30.0,")
        lines.append("    ) -> None:")
        lines.append("        _headers = dict(headers or {})")
        lines.append("        if auth_token:")
        lines.append('            _headers.setdefault("Authorization", f"Bearer {auth_token}")')
        lines.append("        self._client = httpx.Client(")
        lines.append("            base_url=base_url,")
        lines.append("            headers=_headers,")
        lines.append("            timeout=timeout,")
        lines.append("        )")
        lines.append("")
        lines.append("    def close(self) -> None:")
        lines.append('        """Close the underlying HTTP client."""')
        lines.append("        self._client.close()")
        lines.append("")
        lines.append("    def __enter__(self) -> \"" + self._class_name + "\":")
        lines.append("        return self")
        lines.append("")
        lines.append("    def __exit__(self, *args: Any) -> None:")
        lines.append("        self.close()")

        for m in self._methods:
            lines.append("")
            lines.append(self._render_method(m))

        return "\n".join(lines)

    def _render_method(self, m: _Method) -> str:
        lines: List[str] = []

        # Build parameter list
        sig_parts: List[str] = ["self"]
        path_params: List[_MethodParam] = []
        query_params: List[_MethodParam] = []
        header_params: List[_MethodParam] = []

        for p in m.params:
            if p.location == "path":
                path_params.append(p)
            elif p.location == "header":
                header_params.append(p)
            else:
                query_params.append(p)

        # Required params first
        for p in sorted(m.params, key=lambda x: (not x.required, x.name)):
            if p.required:
                sig_parts.append(f"{p.name}: {p.python_type}")
            else:
                sig_parts.append(f"{p.name}: Optional[{p.python_type}] = None")

        # Body param
        if m.body_model:
            sig_parts.append(f"body: {m.body_type} | Dict[str, Any] | None = None")

        # Build signature
        if len(sig_parts) <= 3:
            sig = ", ".join(sig_parts)
            lines.append(f"    def {m.name}({sig}) -> httpx.Response:")
        else:
            lines.append(f"    def {m.name}(")
            for i, part in enumerate(sig_parts):
                comma = "," if i < len(sig_parts) - 1 else ","
                lines.append(f"        {part}{comma}")
            lines.append("    ) -> httpx.Response:")

        # Docstring
        doc_parts = [m.summary] if m.summary else [f"{m.http_method} {m.path}"]
        if m.deprecated:
            doc_parts.insert(0, "**DEPRECATED**")
        lines.append(f'        """{" ".join(doc_parts)}"""')

        # Path formatting
        path_expr = m.path
        for p in path_params:
            # Replace {original_name} with Python f-string using snake_case name
            # Try the snake_case name directly
            path_expr = path_expr.replace("{" + p.name + "}", "{" + p.name + "}")
            # Also try original casing from the OpenAPI param name
            for pm in m.params:
                if pm.location == "path":
                    # The original name may differ from snake_case
                    path_expr = path_expr.replace("{" + pm.description + "}", "{" + pm.name + "}")
        # Handle any remaining {camelCase} path params by trying snake conversion
        for p in path_params:
            for match in re.findall(r"\{([^}]+)\}", path_expr):
                if _snake_case(match) == p.name:
                    path_expr = path_expr.replace("{" + match + "}", "{" + p.name + "}")
        lines.append(f'        url = f"{path_expr}"')

        # Query params
        if query_params:
            lines.append("        params: Dict[str, Any] = {}")
            for p in query_params:
                if p.required:
                    lines.append(f'        params["{p.name}"] = {p.name}')
                else:
                    lines.append(f"        if {p.name} is not None:")
                    lines.append(f'            params["{p.name}"] = {p.name}')

        # Headers
        if header_params:
            lines.append("        _headers: Dict[str, str] = {}")
            for p in header_params:
                if p.required:
                    lines.append(f'        _headers["{p.name}"] = str({p.name})')
                else:
                    lines.append(f"        if {p.name} is not None:")
                    lines.append(f'            _headers["{p.name}"] = str({p.name})')

        # Body
        if m.body_model:
            lines.append("        _json = body.to_dict() if hasattr(body, 'to_dict') else body")

        # Request call
        call_args = [f'"{m.http_method}"', "url"]
        if query_params:
            call_args.append("params=params")
        if header_params:
            call_args.append("headers=_headers")
        if m.body_model:
            call_args.append("json=_json")

        if len(call_args) <= 3:
            lines.append(f"        return self._client.request({', '.join(call_args)})")
        else:
            lines.append("        return self._client.request(")
            for i, arg in enumerate(call_args):
                comma = "," if i < len(call_args) - 1 else ","
                lines.append(f"            {arg}{comma}")
            lines.append("        )")

        return "\n".join(lines)
