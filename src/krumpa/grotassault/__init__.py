"""
GrotAssault — Mutation Fuzzing module.

Responsibilities:
    - Payload generation via mutation strategies (injection, boundary, encoding)
    - Fuzz target parameters, headers, and body fields
    - Anomaly detection (5xx errors, timeouts, stack traces, size deviations)
"""

from krumpa.grotassault.mutator import Mutator, MutationStrategy
from krumpa.grotassault.fuzzer import Fuzzer, FuzzTarget
from krumpa.grotassault.xxe_payloads import XxeChecker, ALL_XXE_PAYLOADS
from krumpa.grotassault.ssrf_payloads import SsrfChecker, ALL_SSRF_PAYLOADS
from krumpa.grotassault.nosql_payloads import NoSqlChecker, ALL_NOSQL_PAYLOADS
from krumpa.grotassault.crlf_payloads import CrlfChecker, ALL_CRLF_PAYLOADS
from krumpa.grotassault.smuggling import HttpSmugglingChecker
from krumpa.grotassault.blind_oob import BlindOobDetector
from krumpa.grotassault.deserialization import DeserializationChecker
from krumpa.grotassault.content_type import ContentTypeSwitcher
from krumpa.grotassault.path_traversal import PathTraversalChecker
from krumpa.grotassault.open_redirect import OpenRedirectChecker
from krumpa.grotassault.encoding_variants import EncodingVariantGenerator
from krumpa.grotassault.module import GrotAssaultModule

__all__ = [
    "GrotAssaultModule",
    "Mutator",
    "MutationStrategy",
    "Fuzzer",
    "FuzzTarget",
    "XxeChecker",
    "ALL_XXE_PAYLOADS",
    "SsrfChecker",
    "ALL_SSRF_PAYLOADS",
    "NoSqlChecker",
    "ALL_NOSQL_PAYLOADS",
    "CrlfChecker",
    "ALL_CRLF_PAYLOADS",
    "HttpSmugglingChecker",
    "BlindOobDetector",
    "DeserializationChecker",
    "ContentTypeSwitcher",
    "PathTraversalChecker",
    "OpenRedirectChecker",
    "EncodingVariantGenerator",
]
