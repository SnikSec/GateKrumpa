"""
OpenKrump — API-First / OpenAPI-Driven Testing module.

Responsibilities:
    - Parse OpenAPI / Swagger specs
    - Auto-generate targets from spec endpoints
    - Validate API responses against their declared schemas
    - Detect undocumented endpoints and missing security definitions
"""

from krumpa.openkrump.parser import SpecParser, ParsedEndpoint
from krumpa.openkrump.validator import SchemaValidator, ValidationIssue
from krumpa.openkrump.bola_generator import BolaGenerator, BolaTestCase
from krumpa.openkrump.schema_validator import ResponseSchemaValidator, SchemaViolation
from krumpa.openkrump.spec_mass_assignment import SpecMassAssignmentChecker, SpecMassAssignmentResult
from krumpa.openkrump.graphql_analyzer import GraphqlAnalyzer
from krumpa.openkrump.swagger2 import Swagger2Parser
from krumpa.openkrump.excessive_data import ExcessiveDataDetector
from krumpa.openkrump.module import OpenKrumpModule

__all__ = [
    "OpenKrumpModule",
    "SpecParser",
    "ParsedEndpoint",
    "SchemaValidator",
    "ValidationIssue",
    "BolaGenerator",
    "BolaTestCase",
    "ResponseSchemaValidator",
    "SchemaViolation",
    "SpecMassAssignmentChecker",
    "SpecMassAssignmentResult",
    "GraphqlAnalyzer",
    "Swagger2Parser",
    "ExcessiveDataDetector",
]
