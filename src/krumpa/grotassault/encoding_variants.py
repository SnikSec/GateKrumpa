"""
GrotAssault — Encoding variant generator for payload enrichment.

Produces multiple encoding variants of base payloads to bypass WAFs
and input filters.
"""

from __future__ import annotations

import html
import urllib.parse
from typing import List


class EncodingVariantGenerator:
    """Generate multiple encoding variants of a base payload string."""

    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        return html.escape(payload, quote=True)

    @staticmethod
    def html_numeric_encode(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def mixed_case(payload: str) -> str:
        result = []
        for i, c in enumerate(payload):
            result.append(c.upper() if i % 2 == 0 else c.lower())
        return "".join(result)

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload + "%00"

    @staticmethod
    def tab_inject(payload: str) -> str:
        """Insert tabs between characters to bypass naive filters."""
        return "\t".join(payload)

    @staticmethod
    def concatenation_bypass(payload: str) -> str:
        """SQL-style comment/concat bypass."""
        mid = len(payload) // 2
        return payload[:mid] + "/**/" + payload[mid:]

    def generate_variants(self, payload: str) -> List[str]:
        """Return the original payload plus all encoded variants."""
        variants = [
            payload,
            self.url_encode(payload),
            self.double_url_encode(payload),
            self.html_entity_encode(payload),
            self.html_numeric_encode(payload),
            self.hex_encode(payload),
            self.unicode_encode(payload),
            self.mixed_case(payload),
            self.null_byte_inject(payload),
            self.tab_inject(payload),
            self.concatenation_bypass(payload),
        ]
        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique
