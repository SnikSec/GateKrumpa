"""Tests for import/export converters — HAR, Burp XML, ZAP JSON."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from krumpa.core.recorder import RequestRecord
from krumpa.core.exchange import (
    export_har,
    import_har,
    import_burp_xml,
    import_zap_json,
    _parse_query,  # pyright: ignore[reportPrivateUsage]
    _parse_raw_headers,  # pyright: ignore[reportPrivateUsage]
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_record(
    method: str = "GET",
    url: str = "https://example.com/api/users",
    status_code: int = 200,
    request_headers: dict[str, str] | None = None,
    response_headers: dict[str, str] | None = None,
    timestamp: datetime | None = None,
    duration_ms: float = 42.5,
    request_body: str | None = None,
    response_body_preview: str = '{"users": []}',
) -> RequestRecord:
    return RequestRecord(
        method=method,
        url=url,
        status_code=status_code,
        request_headers=request_headers if request_headers is not None else {"Host": "example.com", "Accept": "application/json"},
        response_headers=response_headers if response_headers is not None else {"Content-Type": "application/json"},
        timestamp=timestamp or datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        duration_ms=duration_ms,
        request_body=request_body,
        response_body_preview=response_body_preview,
    )


# ==================================================================
# HAR export
# ==================================================================

class TestHarExport:

    def test_basic_structure(self):
        har = export_har([_make_record()])
        assert "log" in har
        assert har["log"]["version"] == "1.2"
        assert "creator" in har["log"]
        assert len(har["log"]["entries"]) == 1

    def test_entry_request_fields(self):
        rec = _make_record(method="POST", request_body='{"name": "test"}')
        har = export_har([rec])
        entry = har["log"]["entries"][0]
        req = entry["request"]
        assert req["method"] == "POST"
        assert req["url"] == rec.url
        assert "postData" in req
        assert req["postData"]["text"] == '{"name": "test"}'

    def test_entry_response_fields(self):
        har = export_har([_make_record()])
        resp = har["log"]["entries"][0]["response"]
        assert resp["status"] == 200
        assert resp["content"]["text"] == '{"users": []}'

    def test_headers_as_list_of_dicts(self):
        har = export_har([_make_record()])
        req_headers = har["log"]["entries"][0]["request"]["headers"]
        assert isinstance(req_headers, list)
        assert all("name" in h and "value" in h for h in req_headers)
        names = {h["name"] for h in req_headers}
        assert "Host" in names

    def test_no_post_data_for_get(self):
        har = export_har([_make_record(method="GET", request_body=None)])
        assert "postData" not in har["log"]["entries"][0]["request"]

    def test_multiple_records(self):
        records = [
            _make_record(url="https://a.com/1"),
            _make_record(url="https://a.com/2"),
            _make_record(url="https://a.com/3"),
        ]
        har = export_har(records)
        assert len(har["log"]["entries"]) == 3

    def test_empty_records(self):
        har = export_har([])
        assert har["log"]["entries"] == []

    def test_custom_creator(self):
        har = export_har([], creator="MyTool 1.0")
        assert har["log"]["creator"]["name"] == "MyTool 1.0"

    def test_query_string_parsed(self):
        rec = _make_record(url="https://example.com/search?q=test&page=1")
        har = export_har([rec])
        qs = har["log"]["entries"][0]["request"]["queryString"]
        names = {p["name"] for p in qs}
        assert "q" in names
        assert "page" in names

    def test_timings_present(self):
        har = export_har([_make_record(duration_ms=100.0)])
        timings = har["log"]["entries"][0]["timings"]
        assert timings["wait"] == 100.0


# ==================================================================
# HAR import
# ==================================================================

class TestHarImport:

    def _minimal_har(self, entries):
        return {"log": {"version": "1.2", "entries": entries}}

    def _entry(self, **overrides):
        defaults = {
            "startedDateTime": "2026-01-15T12:00:00+00:00",
            "time": 50,
            "request": {
                "method": "GET",
                "url": "https://example.com/api",
                "headers": [{"name": "Host", "value": "example.com"}],
            },
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"text": '{"ok": true}'},
            },
        }
        defaults.update(overrides)
        return defaults

    def test_basic_import(self):
        har = self._minimal_har([self._entry()])
        targets, records = import_har(har)
        assert len(targets) == 1
        assert len(records) == 1
        assert targets[0].url == "https://example.com/api"
        assert records[0].status_code == 200

    def test_deduplicates_targets(self):
        har = self._minimal_har([self._entry(), self._entry()])
        targets, records = import_har(har)
        assert len(targets) == 1
        assert len(records) == 2

    def test_different_methods_are_separate_targets(self):
        e1 = self._entry()
        e2 = self._entry()
        e2["request"]["method"] = "POST"
        e2["request"]["postData"] = {"text": "body"}
        har = self._minimal_har([e1, e2])
        targets, _ = import_har(har)
        assert len(targets) == 2

    def test_post_data_imported(self):
        e = self._entry()
        e["request"]["method"] = "POST"
        e["request"]["postData"] = {"text": '{"key": "val"}'}
        _, records = import_har(self._minimal_har([e]))
        assert records[0].request_body == '{"key": "val"}'

    def test_empty_entries(self):
        targets, records = import_har(self._minimal_har([]))
        assert targets == []
        assert records == []

    def test_missing_url_skipped(self):
        e = self._entry()
        e["request"]["url"] = ""
        targets, _ = import_har(self._minimal_har([e]))
        assert len(targets) == 0

    def test_headers_parsed(self):
        _, records = import_har(self._minimal_har([self._entry()]))
        assert records[0].request_headers["Host"] == "example.com"

    def test_bad_timestamp_fallback(self):
        e = self._entry()
        e["startedDateTime"] = "not-a-date"
        _targets, records = import_har(self._minimal_har([e]))
        assert isinstance(records[0].timestamp, datetime)


# ==================================================================
# HAR round-trip
# ==================================================================

class TestHarRoundTrip:

    def test_export_then_import(self):
        original = [
            _make_record(method="GET", url="https://a.com/1"),
            _make_record(method="POST", url="https://a.com/2",
                         request_body="data=hello"),
        ]
        har = export_har(original)
        targets, records = import_har(har)

        assert len(targets) == 2
        assert len(records) == 2
        urls = {r.url for r in records}
        assert "https://a.com/1" in urls
        assert "https://a.com/2" in urls
        post_rec = next(r for r in records if r.method == "POST")
        assert post_rec.request_body == "data=hello"


# ==================================================================
# Burp XML import
# ==================================================================

class TestBurpXmlImport:

    def _burp_xml(self, items_xml: str) -> str:
        return f'<?xml version="1.0"?>\n<items>{items_xml}</items>'

    def _item(self, url="https://example.com/test", method="GET",
              status="200", request="", response="",
              req_base64=False, resp_base64=False) -> str:
        req_attr = ' base64="true"' if req_base64 else ""
        resp_attr = ' base64="true"' if resp_base64 else ""
        return (
            f"<item>"
            f"<url>{url}</url>"
            f"<method>{method}</method>"
            f"<status>{status}</status>"
            f"<request{req_attr}>{request}</request>"
            f"<response{resp_attr}>{response}</response>"
            f"<time>2026-01-15T12:00:00</time>"
            f"</item>"
        )

    def test_basic_import(self):
        xml = self._burp_xml(self._item())
        targets, records = import_burp_xml(xml)
        assert len(targets) == 1
        assert len(records) == 1
        assert targets[0].url == "https://example.com/test"
        assert records[0].status_code == 200

    def test_base64_request(self):
        raw_req = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\nbodydata"
        encoded = base64.b64encode(raw_req.encode()).decode()
        xml = self._burp_xml(self._item(request=encoded, req_base64=True))
        _, records = import_burp_xml(xml)
        assert records[0].request_headers.get("Host") == "example.com"
        assert records[0].request_body == "bodydata"

    def test_base64_response(self):
        raw_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello</h1>"
        encoded = base64.b64encode(raw_resp.encode()).decode()
        xml = self._burp_xml(self._item(response=encoded, resp_base64=True))
        _, records = import_burp_xml(xml)
        assert records[0].response_headers.get("Content-Type") == "text/html"
        assert "<h1>Hello</h1>" in records[0].response_body_preview

    def test_plaintext_request(self):
        raw_req = "POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}"
        xml = self._burp_xml(self._item(method="POST", request=raw_req))
        _, records = import_burp_xml(xml)
        assert records[0].request_headers.get("Content-Type") == "application/json"
        assert records[0].request_body == "{}"

    def test_multiple_items(self):
        items = (
            self._item(url="https://a.com/1") +
            self._item(url="https://a.com/2") +
            self._item(url="https://a.com/3")
        )
        xml = self._burp_xml(items)
        targets, records = import_burp_xml(xml)
        assert len(targets) == 3
        assert len(records) == 3

    def test_deduplicates_targets(self):
        items = self._item() + self._item()
        xml = self._burp_xml(items)
        targets, records = import_burp_xml(xml)
        assert len(targets) == 1
        assert len(records) == 2

    def test_missing_url_skipped(self):
        xml = self._burp_xml(self._item(url=""))
        targets, _ = import_burp_xml(xml)
        assert len(targets) == 0

    def test_empty_items(self):
        xml = self._burp_xml("")
        targets, records = import_burp_xml(xml)
        assert targets == []
        assert records == []


# ==================================================================
# ZAP JSON import
# ==================================================================

class TestZapJsonImport:

    def _msg(self, **overrides):
        defaults = {
            "url": "https://example.com/zap",
            "method": "GET",
            "statusCode": 200,
            "requestHeader": "GET /zap HTTP/1.1\r\nHost: example.com\r\n",
            "requestBody": "",
            "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            "responseBody": "<html></html>",
            "timestamp": 1737014400000,  # 2025-01-16 12:00:00 UTC
        }
        defaults.update(overrides)
        return defaults

    def test_basic_import(self):
        targets, records = import_zap_json([self._msg()])
        assert len(targets) == 1
        assert len(records) == 1
        assert targets[0].url == "https://example.com/zap"
        assert records[0].method == "GET"

    def test_headers_parsed(self):
        _, records = import_zap_json([self._msg()])
        assert records[0].request_headers.get("Host") == "example.com"

    def test_response_body_captured(self):
        _, records = import_zap_json([self._msg(responseBody="<h1>OK</h1>")])
        assert "<h1>OK</h1>" in records[0].response_body_preview

    def test_timestamp_converted(self):
        _, records = import_zap_json([self._msg(timestamp=1737014400000)])
        assert records[0].timestamp.year == 2025

    def test_zero_timestamp_fallback(self):
        _, records = import_zap_json([self._msg(timestamp=0)])
        assert isinstance(records[0].timestamp, datetime)

    def test_deduplicates_targets(self):
        targets, records = import_zap_json([self._msg(), self._msg()])
        assert len(targets) == 1
        assert len(records) == 2

    def test_different_urls_separate(self):
        targets, _ = import_zap_json([
            self._msg(url="https://a.com/1"),
            self._msg(url="https://a.com/2"),
        ])
        assert len(targets) == 2

    def test_missing_url_skipped(self):
        targets, _ = import_zap_json([self._msg(url="")])
        assert len(targets) == 0

    def test_empty_list(self):
        targets, records = import_zap_json([])
        assert targets == []
        assert records == []

    def test_request_body_captured(self):
        _, records = import_zap_json([self._msg(
            method="POST",
            requestBody='{"key": "val"}',
        )])
        assert records[0].request_body == '{"key": "val"}'

    def test_empty_request_body_is_none(self):
        _, records = import_zap_json([self._msg(requestBody="")])
        assert records[0].request_body is None

    def test_uri_fallback_field(self):
        """ZAP may use 'uri' instead of 'url'."""
        msg = self._msg()
        del msg["url"]
        msg["uri"] = "https://example.com/alt"
        targets, _ = import_zap_json([msg])
        assert len(targets) == 1
        assert targets[0].url == "https://example.com/alt"

    def test_response_body_truncated(self):
        long_body = "x" * 1000
        _, records = import_zap_json([self._msg(responseBody=long_body)])
        assert len(records[0].response_body_preview) <= 500


# ==================================================================
# Helper functions
# ==================================================================

class TestParseQuery:

    def test_simple_query(self):
        result = _parse_query("https://example.com/search?q=test&page=1")
        names = {p["name"] for p in result}
        assert "q" in names
        assert "page" in names

    def test_no_query(self):
        assert _parse_query("https://example.com/path") == []

    def test_key_without_value(self):
        result = _parse_query("https://example.com/?flag")
        assert result[0]["name"] == "flag"
        assert result[0]["value"] == ""


class TestParseRawHeaders:

    def test_parses_headers(self):
        raw = "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        h = _parse_raw_headers(raw)
        assert h["Host"] == "example.com"
        assert h["Accept"] == "*/*"

    def test_skips_request_line(self):
        raw = "POST /api HTTP/1.1\r\nContent-Type: text/plain\r\n"
        h = _parse_raw_headers(raw)
        assert "POST /api HTTP/1.1" not in h
        assert h["Content-Type"] == "text/plain"

    def test_skips_status_line(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx\r\n"
        h = _parse_raw_headers(raw)
        assert h["Server"] == "nginx"

    def test_empty_string(self):
        assert _parse_raw_headers("") == {}
