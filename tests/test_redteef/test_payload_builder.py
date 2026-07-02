"""Tests for krumpa.redteef.payload_builder — PoC payload builder."""

from krumpa.redteef.payload_builder import PayloadBuilder, ProofPayload


class TestSupportedTypes:
    def test_has_common_types(self):
        b = PayloadBuilder()
        types = b.supported_types
        for t in ["sqli", "xss", "ssti", "cmdi", "idor"]:
            assert t in types

    def test_extra_canaries_extend_catalogue(self):
        extra = {"custom": [ProofPayload(vuln_type="custom", payload="test", expected_indicator="ok")]}
        b = PayloadBuilder(extra_canaries=extra)
        assert "custom" in b.supported_types


class TestBuild:
    def test_returns_payloads_for_known_type(self):
        b = PayloadBuilder()
        payloads = b.build("xss")
        assert len(payloads) > 0
        assert all(isinstance(p, ProofPayload) for p in payloads)

    def test_returns_empty_for_unknown_type(self):
        b = PayloadBuilder()
        assert b.build("doesnotexist") == []

    def test_sets_inject_field(self):
        b = PayloadBuilder()
        payloads = b.build("xss", inject_field="search_query")
        for p in payloads:
            assert p.inject_field == "search_query"

    def test_sets_http_method(self):
        b = PayloadBuilder()
        payloads = b.build("ssti", http_method="PUT")
        for p in payloads:
            assert p.http_method == "PUT"

    def test_sets_inject_location(self):
        b = PayloadBuilder()
        payloads = b.build("cmdi", inject_location="header")
        for p in payloads:
            assert p.inject_location == "header"

    def test_xss_canaries_have_expected_indicator(self):
        b = PayloadBuilder()
        payloads = b.build("xss")
        for p in payloads:
            assert p.expected_indicator, "XSS canaries should have an expected indicator"

    def test_ssti_canaries_expect_1337(self):
        b = PayloadBuilder()
        payloads = b.build("ssti")
        assert any(p.expected_indicator == "1337" for p in payloads)


class TestInferVulnType:
    def test_infers_sqli_from_tags(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["sql", "fuzz"]) == "sqli"

    def test_infers_xss_from_tags(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["xss"]) == "xss"

    def test_infers_from_title(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type([], "Reflected XSS in search") == "xss"

    def test_infers_ssti_from_tags(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["template"]) == "ssti"

    def test_infers_cmdi_from_tags(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["command"]) == "cmdi"

    def test_infers_idor_from_tags(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["idor"]) == "idor"

    def test_returns_none_for_unknown(self):
        b = PayloadBuilder()
        assert b.infer_vuln_type(["unknown-tag"]) is None
