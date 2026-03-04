"""Tests for the SDK generator — typed Python client from OpenAPI specs."""

from __future__ import annotations

import ast

from krumpa.openkrump.parser import ParsedEndpoint, SpecParser
from krumpa.openkrump.sdk_generator import (
    generate_sdk,
    _safe_identifier,  # pyright: ignore[reportPrivateUsage]
    _snake_case,  # pyright: ignore[reportPrivateUsage]
    _pascal_case,  # pyright: ignore[reportPrivateUsage]
)


# ------------------------------------------------------------------
# Fixtures / helpers
# ------------------------------------------------------------------

def _petstore_spec() -> dict:
    """Minimal OpenAPI 3.0 Petstore-like spec."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Petstore", "version": "1.0.0"},
        "servers": [{"url": "https://api.petstore.io/v1"}],
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "listPets",
                    "summary": "List all pets",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/Pet"},
                                    }
                                }
                            }
                        }
                    },
                },
                "post": {
                    "operationId": "createPet",
                    "summary": "Create a pet",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Pet"},
                            }
                        }
                    },
                    "responses": {"201": {}},
                },
            },
            "/pets/{petId}": {
                "get": {
                    "operationId": "showPetById",
                    "summary": "Info for a specific pet",
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Pet"},
                                }
                            }
                        }
                    },
                },
                "delete": {
                    "operationId": "deletePet",
                    "summary": "Delete a pet",
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                    ],
                    "responses": {"204": {}},
                    "deprecated": True,
                },
            },
        },
        "components": {
            "schemas": {
                "Pet": {
                    "type": "object",
                    "required": ["id", "name"],
                    "properties": {
                        "id": {"type": "integer", "description": "Pet ID"},
                        "name": {"type": "string", "description": "Pet name"},
                        "tag": {"type": "string", "description": "Optional tag"},
                    },
                }
            }
        },
    }


def _parse(spec: dict) -> list[ParsedEndpoint]:
    return SpecParser().parse(spec)


# ==================================================================
# Naming helpers
# ==================================================================

class TestNamingHelpers:

    def test_safe_identifier_keyword(self):
        assert _safe_identifier("class") == "class_"

    def test_safe_identifier_leading_digit(self):
        assert _safe_identifier("3xx") == "_3xx"

    def test_safe_identifier_special_chars(self):
        assert _safe_identifier("my-var.name") == "my_var_name"

    def test_snake_case_camel(self):
        assert _snake_case("listPets") == "list_pets"

    def test_snake_case_pascal(self):
        assert _snake_case("ShowPetById") == "show_pet_by_id"

    def test_snake_case_kebab(self):
        assert _snake_case("get-all-users") == "get_all_users"

    def test_pascal_case(self):
        assert _pascal_case("pet_store") == "PetStore"

    def test_pascal_case_from_kebab(self):
        assert _pascal_case("my-model") == "MyModel"


# ==================================================================
# Full SDK generation
# ==================================================================

class TestGenerateSdk:

    def test_produces_valid_python(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        # Must be parseable as Python
        ast.parse(code)

    def test_contains_client_class(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "class ApiClient:" in code

    def test_custom_class_name(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1",
                            class_name="PetstoreClient")
        assert "class PetstoreClient:" in code

    def test_methods_generated(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "def list_pets(" in code
        assert "def create_pet(" in code
        assert "def show_pet_by_id(" in code
        assert "def delete_pet(" in code

    def test_model_generated(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "class Pet:" in code
        assert "@dataclass" in code

    def test_model_fields(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "id: int" in code
        assert "name: str" in code
        assert "tag: Optional[str]" in code

    def test_model_to_dict(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "def to_dict(self)" in code

    def test_deprecated_method_docstring(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "DEPRECATED" in code

    def test_base_url_in_init(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "https://api.petstore.io/v1" in code

    def test_httpx_import(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "import httpx" in code

    def test_context_manager(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "def __enter__" in code
        assert "def __exit__" in code

    def test_auth_token_param(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        assert "auth_token" in code

    def test_query_param_in_method(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        # listPets has a 'limit' query param
        assert "limit" in code

    def test_path_param_in_url(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        # showPetById or deletePet should have f-string path with pet_id
        assert "pet_id" in code

    def test_body_param_for_post(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1")
        # createPet should have a body param
        assert "body:" in code

    def test_custom_docstring(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, _parse(spec), "https://api.petstore.io/v1",
                            module_docstring="My custom SDK")
        assert "My custom SDK" in code

    def test_empty_endpoints(self):
        spec = _petstore_spec()
        code = generate_sdk(spec, [], "https://api.petstore.io/v1")
        # Should still produce a valid class with no methods
        ast.parse(code)
        assert "class ApiClient:" in code


# ==================================================================
# Swagger 2.0 spec
# ==================================================================

class TestSwagger2Sdk:

    def _swagger2_spec(self) -> dict:
        return {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "0.9"},
            "host": "old-api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "summary": "List users",
                        "parameters": [
                            {"name": "page", "in": "query", "type": "integer"},
                        ],
                        "responses": {"200": {"schema": {"type": "array"}}},
                    },
                    "post": {
                        "operationId": "createUser",
                        "parameters": [
                            {
                                "name": "body",
                                "in": "body",
                                "schema": {"$ref": "#/definitions/User"},
                            }
                        ],
                        "responses": {"201": {}},
                    },
                },
            },
            "definitions": {
                "User": {
                    "type": "object",
                    "required": ["email"],
                    "properties": {
                        "email": {"type": "string"},
                        "name": {"type": "string"},
                        "age": {"type": "integer"},
                    },
                }
            },
        }

    def test_swagger2_valid_python(self):
        spec = self._swagger2_spec()
        code = generate_sdk(spec, _parse(spec), "https://old-api.example.com/v1")
        ast.parse(code)

    def test_swagger2_methods(self):
        spec = self._swagger2_spec()
        code = generate_sdk(spec, _parse(spec), "https://old-api.example.com/v1")
        assert "def get_users(" in code
        assert "def create_user(" in code

    def test_swagger2_model(self):
        spec = self._swagger2_spec()
        code = generate_sdk(spec, _parse(spec), "https://old-api.example.com/v1")
        assert "class User:" in code
        assert "email: str" in code


# ==================================================================
# Edge cases
# ==================================================================

class TestEdgeCases:

    def test_no_operation_id_fallback(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/items": {
                    "get": {
                        "responses": {"200": {}},
                    }
                }
            },
        }
        code = generate_sdk(spec, _parse(spec), "http://localhost")
        ast.parse(code)
        assert "def get_items(" in code

    def test_duplicate_operation_ids_get_suffix(self):
        ep1 = ParsedEndpoint(path="/a", method="GET", operation_id="listAll")
        ep2 = ParsedEndpoint(path="/b", method="GET", operation_id="listAll")
        spec = {"openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"}}
        code = generate_sdk(spec, [ep1, ep2], "http://localhost")
        assert "def list_all(" in code
        assert "def list_all_2(" in code

    def test_nested_ref_model(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/orders": {
                    "post": {
                        "operationId": "createOrder",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"},
                                }
                            }
                        },
                        "responses": {"201": {}},
                    }
                }
            },
            "components": {
                "schemas": {
                    "Order": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "items": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/OrderItem"},
                            },
                        },
                    },
                    "OrderItem": {
                        "type": "object",
                        "properties": {
                            "product": {"type": "string"},
                            "quantity": {"type": "integer"},
                        },
                    },
                }
            },
        }
        code = generate_sdk(spec, _parse(spec), "http://localhost")
        ast.parse(code)
        assert "class Order:" in code
        assert "class OrderItem:" in code

    def test_additional_properties_map_type(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/config": {
                    "get": {
                        "operationId": "getConfig",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "additionalProperties": {"type": "string"},
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            },
        }
        code = generate_sdk(spec, _parse(spec), "http://localhost")
        ast.parse(code)

    def test_header_params(self):
        ep = ParsedEndpoint(
            path="/secure",
            method="GET",
            operation_id="secureEndpoint",
            parameters=[
                {"name": "X-Api-Key", "in": "header", "required": True,
                 "schema": {"type": "string"}},
            ],
        )
        spec = {"openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"}}
        code = generate_sdk(spec, [ep], "http://localhost")
        ast.parse(code)
        assert "x_api_key" in code

    def test_format_override_datetime(self):
        ep = ParsedEndpoint(
            path="/events",
            method="GET",
            operation_id="listEvents",
            parameters=[
                {"name": "since", "in": "query",
                 "schema": {"type": "string", "format": "date-time"}},
            ],
        )
        spec = {"openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"}}
        code = generate_sdk(spec, [ep], "http://localhost")
        # date-time maps to str
        assert "since: str" in code or "since:" in code
