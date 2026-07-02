"""Tests for SessionAnalyzer — cookie and JWT analysis."""

from __future__ import annotations

import base64
import json


from krumpa.core import Severity, Target
from krumpa.bosskey.session_analyzer import SessionAnalyzer


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _target() -> Target:
    return Target(url="https://example.com")


def _make_jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    """Build a raw JWT string from parts."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{signature}"


# ------------------------------------------------------------------
# Cookie parsing
# ------------------------------------------------------------------

class TestParseCookie:

    def test_basic_name_value(self):
        c = SessionAnalyzer.parse_cookie("session=abc123")
        assert c.name == "session"
        assert c.value == "abc123"

    def test_secure_flag(self):
        c = SessionAnalyzer.parse_cookie("id=val; Secure")
        assert c.secure is True

    def test_httponly_flag(self):
        c = SessionAnalyzer.parse_cookie("id=val; HttpOnly")
        assert c.httponly is True

    def test_samesite_strict(self):
        c = SessionAnalyzer.parse_cookie("id=val; SameSite=Strict")
        assert c.samesite == "Strict"

    def test_samesite_lax(self):
        c = SessionAnalyzer.parse_cookie("id=val; SameSite=Lax")
        assert c.samesite == "Lax"

    def test_path_and_domain(self):
        c = SessionAnalyzer.parse_cookie("id=val; Path=/api; Domain=.example.com")
        assert c.path == "/api"
        assert c.domain == ".example.com"

    def test_max_age(self):
        c = SessionAnalyzer.parse_cookie("id=val; Max-Age=3600")
        assert c.max_age == 3600

    def test_all_flags_combined(self):
        c = SessionAnalyzer.parse_cookie(
            "tok=xyz; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
        )
        assert c.secure is True
        assert c.httponly is True
        assert c.samesite == "Strict"
        assert c.max_age == 86400

    def test_no_equals_in_value(self):
        c = SessionAnalyzer.parse_cookie("flag")
        assert c.name == "flag"
        assert c.value == ""


# ------------------------------------------------------------------
# Shannon entropy
# ------------------------------------------------------------------

class TestShannonEntropy:

    def test_empty_string(self):
        assert SessionAnalyzer.shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert SessionAnalyzer.shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → 1.0 bits/char
        e = SessionAnalyzer.shannon_entropy("ab")
        assert abs(e - 1.0) < 0.01

    def test_high_entropy_hex(self):
        # 32-char hex with good distribution should be > 3.0
        val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        e = SessionAnalyzer.shannon_entropy(val)
        assert e > 3.0


# ------------------------------------------------------------------
# Cookie flag checks
# ------------------------------------------------------------------

class TestAnalyseCookies:

    def test_missing_secure_on_https(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_cookies(
            ["session=abc; HttpOnly; SameSite=Strict"],
            _target(),
            is_https=True,
        )
        titles = [f.title for f in findings]
        assert any("Secure flag" in t for t in titles)

    def test_missing_httponly(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_cookies(
            ["session=abc; Secure; SameSite=Strict"],
            _target(),
            is_https=True,
        )
        titles = [f.title for f in findings]
        assert any("HttpOnly" in t for t in titles)

    def test_weak_samesite(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_cookies(
            ["session=abc; Secure; HttpOnly"],
            _target(),
            is_https=True,
        )
        titles = [f.title for f in findings]
        assert any("SameSite" in t for t in titles)

    def test_no_findings_for_fully_secured_cookie(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_cookies(
            ["session=a1b2c3d4e5f6a7b8; Secure; HttpOnly; SameSite=Strict"],
            _target(),
            is_https=True,
        )
        # Only acceptable finding would be entropy-related
        flag_findings = [f for f in findings if "flag" in f.title.lower() or "SameSite" in f.title]
        assert flag_findings == []

    def test_low_entropy_finding(self):
        sa = SessionAnalyzer(min_entropy_bits=3.5)
        findings = sa.analyse_cookies(
            ["session=aaaaaaaa; Secure; HttpOnly; SameSite=Strict"],
            _target(),
            is_https=True,
        )
        entropy_findings = [f for f in findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) == 1
        assert entropy_findings[0].severity == Severity.HIGH

    def test_no_secure_flag_finding_on_http(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_cookies(
            ["session=abc; HttpOnly; SameSite=Strict"],
            _target(),
            is_https=False,
        )
        titles = [f.title for f in findings]
        assert not any("Secure flag" in t for t in titles)


# ------------------------------------------------------------------
# JWT decoding
# ------------------------------------------------------------------

class TestDecodeJWT:

    def test_decode_valid_jwt(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "user1", "exp": 9999999999})
        jwt = SessionAnalyzer.decode_jwt(token)
        assert jwt.algorithm == "HS256"
        assert jwt.payload["sub"] == "user1"
        assert jwt.signature_present is True

    def test_empty_signature(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "user1"}, signature="")
        jwt = SessionAnalyzer.decode_jwt(token)
        assert jwt.signature_present is False

    def test_alg_none(self):
        token = _make_jwt({"alg": "none"}, {"sub": "admin"}, signature="")
        jwt = SessionAnalyzer.decode_jwt(token)
        assert jwt.algorithm == "none"

    def test_malformed_token(self):
        jwt = SessionAnalyzer.decode_jwt("not-a-jwt")
        assert len(jwt.errors) > 0


# ------------------------------------------------------------------
# JWT vulnerability checks
# ------------------------------------------------------------------

class TestAnalyseTokens:

    def test_alg_none_critical(self):
        sa = SessionAnalyzer()
        token = _make_jwt({"alg": "none"}, {"sub": "admin"}, signature="")
        findings = sa.analyse_tokens([f"Bearer {token}"], _target())
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("none" in f.title.lower() for f in findings)

    def test_missing_exp_finding(self):
        sa = SessionAnalyzer()
        token = _make_jwt({"alg": "HS256"}, {"sub": "user1"})
        findings = sa.analyse_tokens([f"Bearer {token}"], _target())
        assert any("exp" in f.title.lower() for f in findings)

    def test_no_finding_when_exp_present(self):
        sa = SessionAnalyzer()
        token = _make_jwt({"alg": "RS256"}, {"sub": "user1", "exp": 9999999999})
        findings = sa.analyse_tokens([f"Bearer {token}"], _target())
        exp_findings = [f for f in findings if "exp" in f.title.lower()]
        assert exp_findings == []

    def test_hmac_missing_signature(self):
        sa = SessionAnalyzer()
        token = _make_jwt({"alg": "HS256"}, {"sub": "user1", "exp": 9999999999}, signature="")
        findings = sa.analyse_tokens([f"Bearer {token}"], _target())
        assert any("signature" in f.title.lower() for f in findings)

    def test_deduplicates_same_token(self):
        sa = SessionAnalyzer()
        token = _make_jwt({"alg": "none"}, {"sub": "admin"}, signature="")
        findings = sa.analyse_tokens([token, token, token], _target())
        # Should not produce 3× the findings
        none_findings = [f for f in findings if "none" in f.title.lower()]
        assert len(none_findings) == 1

    def test_no_jwt_returns_empty(self):
        sa = SessionAnalyzer()
        findings = sa.analyse_tokens(["not-a-token", "plain-text"], _target())
        assert findings == []
