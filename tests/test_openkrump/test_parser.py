"""Tests for krumpa.openkrump.parser — OpenAPI spec parser."""

import pytest
from krumpa.openkrump.parser import SpecParser, ParsedEndpoint


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _openapi3_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "summary": "List users",
                    "tags": ["users"],
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}},
                                    },
                                },
                            },
                        },
                    },
                },
                "post": {
                    "operationId": "createUser",
                    "summary": "Create user",
                    "tags": ["users"],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                            },
                        },
                    },
                    "responses": {"201": {}},
                    "security": [],
                },
            },
            "/health": {
                "get": {
                    "operationId": "healthCheck",
                    "deprecated": True,
                    "responses": {"200": {}},
                },
            },
        },
    }


def _swagger2_spec() -> dict:
    return {
        "swagger": "2.0",
        "info": {"title": "Legacy API", "version": "0.1"},
        "host": "legacy.example.com",
        "basePath": "/api",
        "schemes": ["https"],
        "paths": {
            "/items": {
                "get": {
                    "operationId": "getItems",
                    "responses": {
                        "200": {
                            "schema": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                },
                "post": {
                    "operationId": "createItem",
                    "parameters": [
                        {"in": "body", "name": "body", "schema": {"type": "object", "properties": {"name": {"type": "string"}}}},
                    ],
                    "responses": {"201": {}},
                },
            },
        },
    }


# ------------------------------------------------------------------
# OpenAPI 3 tests
# ------------------------------------------------------------------

class TestOpenAPI3Parsing:
    def test_parses_endpoints(self):
        parser = SpecParser()
        eps = parser.parse(_openapi3_spec())
        assert len(eps) == 3  # GET /users, POST /users, GET /health

    def test_method_and_path(self):
        eps = SpecParser().parse(_openapi3_spec())
        ids = {ep.full_id for ep in eps}
        assert "GET /users" in ids
        assert "POST /users" in ids

    def test_operation_id(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_get = [e for e in eps if e.operation_id == "listUsers"][0]
        assert user_get.path == "/users"

    def test_parameters(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_get = [e for e in eps if e.operation_id == "listUsers"][0]
        assert len(user_get.parameters) == 1
        assert user_get.parameters[0]["name"] == "limit"

    def test_request_body_schema(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_post = [e for e in eps if e.operation_id == "createUser"][0]
        assert user_post.request_body_schema is not None
        assert user_post.request_body_schema["type"] == "object"

    def test_response_schema(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_get = [e for e in eps if e.operation_id == "listUsers"][0]
        assert "200" in user_get.response_schemas
        assert user_get.response_schemas["200"]["type"] == "array"

    def test_security_inheritance(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_get = [e for e in eps if e.operation_id == "listUsers"][0]
        assert len(user_get.security) > 0  # inherits global security

    def test_operation_level_security_override(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_post = [e for e in eps if e.operation_id == "createUser"][0]
        assert user_post.security == []  # explicitly no security

    def test_deprecated_flag(self):
        eps = SpecParser().parse(_openapi3_spec())
        health = [e for e in eps if e.operation_id == "healthCheck"][0]
        assert health.deprecated

    def test_tags(self):
        eps = SpecParser().parse(_openapi3_spec())
        user_get = [e for e in eps if e.operation_id == "listUsers"][0]
        assert "users" in user_get.tags


# ------------------------------------------------------------------
# Swagger 2.0 tests
# ------------------------------------------------------------------

class TestSwagger2Parsing:
    def test_parses_endpoints(self):
        eps = SpecParser().parse(_swagger2_spec())
        assert len(eps) == 2

    def test_request_body_from_body_param(self):
        eps = SpecParser().parse(_swagger2_spec())
        post = [e for e in eps if e.method == "POST"][0]
        assert post.request_body_schema is not None

    def test_response_schema(self):
        eps = SpecParser().parse(_swagger2_spec())
        get = [e for e in eps if e.method == "GET"][0]
        assert "200" in get.response_schemas


# ------------------------------------------------------------------
# URL resolution
# ------------------------------------------------------------------

class TestResolveUrl:
    def test_openapi3_server(self):
        parser = SpecParser()
        url = parser.resolve_url(_openapi3_spec(), "/users")
        assert url == "https://api.example.com/v1/users"

    def test_swagger2_url(self):
        parser = SpecParser()
        url = parser.resolve_url(_swagger2_spec(), "/items")
        assert url == "https://legacy.example.com/api/items"

    def test_base_url_override(self):
        parser = SpecParser(base_url="http://custom:8080")
        url = parser.resolve_url(_openapi3_spec(), "/users")
        assert url == "http://custom:8080/users"

    def test_empty_spec_fallback(self):
        parser = SpecParser()
        url = parser.resolve_url({}, "/test")
        assert "localhost" in url
