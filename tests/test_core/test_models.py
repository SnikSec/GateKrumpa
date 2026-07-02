"""Tests for core data models: Severity, ModuleStatus, Target, Finding, ScanContext."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from krumpa.core import Finding, ModuleStatus, ScanContext, Severity, Target


# ------------------------------------------------------------------
# Severity enum
# ------------------------------------------------------------------

class TestSeverity:

    def test_members(self):
        assert set(Severity) == {
            Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL,
        }

    def test_values(self):
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_lookup_by_value(self):
        assert Severity("critical") is Severity.CRITICAL

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            Severity("unknown")


# ------------------------------------------------------------------
# ModuleStatus enum
# ------------------------------------------------------------------

class TestModuleStatus:

    def test_members(self):
        expected = {"idle", "running", "completed", "failed", "cancelled"}
        assert {s.value for s in ModuleStatus} == expected

    def test_lookup_by_value(self):
        assert ModuleStatus("running") is ModuleStatus.RUNNING


# ------------------------------------------------------------------
# Target dataclass
# ------------------------------------------------------------------

class TestTarget:

    def test_defaults(self):
        t = Target(url="https://example.com/api")
        assert t.url == "https://example.com/api"
        assert t.method == "GET"
        assert t.headers == {}
        assert t.body is None
        assert t.metadata == {}

    def test_host_property(self):
        t = Target(url="https://api.example.com:8443/v1/users")
        assert t.host == "api.example.com"

    def test_host_fallback_on_bare_string(self):
        t = Target(url="not-a-url")
        # urlparse won't produce a hostname for a bare string
        assert t.host == "not-a-url"

    def test_custom_method_and_headers(self):
        t = Target(url="https://x.com", method="POST", headers={"X-Key": "val"})
        assert t.method == "POST"
        assert t.headers["X-Key"] == "val"

    def test_body(self):
        t = Target(url="https://x.com", body='{"a":1}')
        assert t.body == '{"a":1}'

    def test_metadata_isolation(self):
        """Each instance should get its own metadata dict."""
        a = Target(url="https://a.com")
        b = Target(url="https://b.com")
        a.metadata["x"] = 1
        assert "x" not in b.metadata


# ------------------------------------------------------------------
# Finding dataclass
# ------------------------------------------------------------------

class TestFinding:

    def test_defaults(self):
        f = Finding()
        assert len(f.id) == 12
        assert f.title == ""
        assert f.description == ""
        assert f.severity is Severity.INFO
        assert f.module == ""
        assert f.target is None
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.cwe is None
        assert f.cvss_score is None
        assert f.tags == []
        assert isinstance(f.timestamp, datetime)
        assert f.raw == {}

    def test_unique_ids(self):
        ids = {Finding().id for _ in range(100)}
        assert len(ids) == 100

    def test_to_dict_basic(self):
        t = Target(url="https://api.com/users")
        f = Finding(
            title="SQLi",
            severity=Severity.HIGH,
            module="grotassault",
            target=t,
            cwe=89,
            cvss_score=9.8,
            tags=["injection"],
        )
        d = f.to_dict()
        assert d["title"] == "SQLi"
        assert d["severity"] == "high"
        assert d["module"] == "grotassault"
        assert d["target"] == "https://api.com/users"
        assert d["cwe"] == 89
        assert d["cvss_score"] == 9.8
        assert d["tags"] == ["injection"]
        assert "timestamp" in d

    def test_to_dict_no_target(self):
        f = Finding(title="Generic")
        assert f.to_dict()["target"] is None

    def test_to_dict_has_iso_timestamp(self):
        f = Finding()
        ts = f.to_dict()["timestamp"]
        # Should be valid ISO-8601
        datetime.fromisoformat(ts)

    def test_tags_isolation(self):
        a = Finding()
        b = Finding()
        a.tags.append("x")
        assert "x" not in b.tags

    def test_raw_isolation(self):
        a = Finding()
        b = Finding()
        a.raw["k"] = "v"
        assert "k" not in b.raw


# ------------------------------------------------------------------
# ScanContext dataclass
# ------------------------------------------------------------------

class TestScanContext:

    def test_defaults(self):
        ctx = ScanContext()
        assert len(ctx.scan_id) == 16
        assert ctx.targets == []
        assert ctx.config == {}
        assert ctx.findings == []
        assert ctx.auth_tokens == {}
        assert ctx.metadata == {}
        assert ctx.started_at is None
        assert ctx.finished_at is None

    def test_unique_scan_ids(self):
        ids = {ScanContext().scan_id for _ in range(50)}
        assert len(ids) == 50

    def test_add_finding(self):
        ctx = ScanContext()
        f = Finding(title="XSS")
        ctx.add_finding(f)
        assert len(ctx.findings) == 1
        assert ctx.findings[0] is f

    def test_add_target(self):
        ctx = ScanContext()
        t = Target(url="https://a.com")
        ctx.add_target(t)
        assert len(ctx.targets) == 1
        assert ctx.targets[0] is t

    def test_summary_empty(self):
        ctx = ScanContext()
        s = ctx.summary()
        assert s["total_targets"] == 0
        assert s["total_findings"] == 0
        assert s["findings_by_severity"] == {}
        assert s["started_at"] is None
        assert s["finished_at"] is None

    def test_summary_with_findings(self):
        ctx = ScanContext()
        ctx.add_finding(Finding(title="XSS on /a", severity=Severity.HIGH))
        ctx.add_finding(Finding(title="XSS on /b", severity=Severity.HIGH))
        ctx.add_finding(Finding(title="Missing header", severity=Severity.LOW))
        s = ctx.summary()
        assert s["total_findings"] == 3
        assert s["findings_by_severity"]["high"] == 2
        assert s["findings_by_severity"]["low"] == 1

    def test_summary_with_timestamps(self):
        ctx = ScanContext()
        now = datetime.now(timezone.utc)
        ctx.started_at = now
        ctx.finished_at = now
        s = ctx.summary()
        assert s["started_at"] is not None
        assert s["finished_at"] is not None

    def test_clear_sensitive(self):
        ctx = ScanContext()
        ctx.auth_tokens["bearer"] = "secret-jwt"
        ctx.metadata["cookies"] = {"sid": "abc"}
        ctx.metadata["session"] = {"key": "val"}
        ctx.metadata["safe"] = "keep"

        ctx.clear_sensitive()

        assert ctx.auth_tokens == {}
        assert "cookies" not in ctx.metadata
        assert "session" not in ctx.metadata
        assert ctx.metadata["safe"] == "keep"

    def test_clear_sensitive_noop_when_empty(self):
        ctx = ScanContext()
        ctx.clear_sensitive()  # should not raise
        assert ctx.auth_tokens == {}

    def test_add_multiple_targets_ordering(self):
        ctx = ScanContext()
        urls = [f"https://t{i}.com" for i in range(5)]
        for u in urls:
            ctx.add_target(Target(url=u))
        assert [t.url for t in ctx.targets] == urls

    def test_list_isolation(self):
        a = ScanContext()
        b = ScanContext()
        a.targets.append(Target(url="https://only-a.com"))
        assert len(b.targets) == 0
