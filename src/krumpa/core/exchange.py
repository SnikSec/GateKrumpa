"""
GateKrumpa core — import / export converters.

Converts between GateKrumpa internal formats and external tool formats:
  - **HAR 1.2**  (HTTP Archive) — import & export
  - **Burp XML** (Burp Suite proxy history) — import
  - **ZAP JSON** (OWASP ZAP messages) — import

Import functions return :class:`Target` and :class:`RequestRecord` objects
that can be fed into a :class:`ScanContext` or :class:`RequestRecorder`.

Export functions convert recorded traffic into the target format.
"""

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from krumpa.core import Target
from krumpa.core.recorder import RequestRecord

logger = logging.getLogger("krumpa.exchange")


# ===================================================================
# HAR 1.2  (HTTP Archive)
# ===================================================================

def export_har(records: List[RequestRecord], *, creator: str = "GateKrumpa 0.1.0") -> Dict[str, Any]:
    """Convert recorded traffic to a HAR 1.2 dict.

    Parameters
    ----------
    records:
        Traffic captured by :class:`RequestRecorder`.
    creator:
        Name/version string for the ``creator`` field.

    Returns
    -------
    dict
        A HAR 1.2 archive ready for ``json.dumps()``.
    """
    entries: List[Dict[str, Any]] = []
    for r in records:
        entry: Dict[str, Any] = {
            "startedDateTime": r.timestamp.isoformat(),
            "time": r.duration_ms,
            "request": {
                "method": r.method,
                "url": r.url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in r.request_headers.items()],
                "queryString": _parse_query(r.url),
                "headersSize": -1,
                "bodySize": len(r.request_body) if r.request_body else 0,
            },
            "response": {
                "status": r.status_code,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in r.response_headers.items()],
                "content": {
                    "size": len(r.response_body_preview),
                    "mimeType": r.response_headers.get("content-type", ""),
                    "text": r.response_body_preview,
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(r.response_body_preview),
            },
            "cache": {},
            "timings": {"send": 0, "wait": r.duration_ms, "receive": 0},
        }
        if r.request_body:
            entry["request"]["postData"] = {
                "mimeType": r.request_headers.get("content-type", ""),
                "text": r.request_body,
            }
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "0.1.0"},
            "entries": entries,
        }
    }


def import_har(data: Dict[str, Any]) -> Tuple[List[Target], List[RequestRecord]]:
    """Parse a HAR 1.2 dict into Targets and RequestRecords.

    Parameters
    ----------
    data:
        Parsed HAR JSON (the top-level object with a ``log`` key).

    Returns
    -------
    tuple
        ``(targets, records)`` — deduplicated targets and all records.
    """
    targets: List[Target] = []
    records: List[RequestRecord] = []
    seen_targets: set[str] = set()

    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        if not url:
            continue

        # Headers → dict
        req_headers = {h["name"]: h["value"] for h in req.get("headers", []) if "name" in h}
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", []) if "name" in h}

        # Request body
        body: Optional[str] = None
        post_data = req.get("postData", {})
        if post_data and post_data.get("text"):
            body = post_data["text"]

        # Timestamp
        ts_str = entry.get("startedDateTime", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        records.append(RequestRecord(
            method=method,
            url=url,
            status_code=resp.get("status", 0),
            request_headers=req_headers,
            response_headers=resp_headers,
            timestamp=ts,
            duration_ms=entry.get("time", 0),
            request_body=body,
            response_body_preview=resp.get("content", {}).get("text", ""),
        ))

        key = f"{method}:{url}"
        if key not in seen_targets:
            seen_targets.add(key)
            targets.append(Target(url=url, method=method, headers=req_headers))

    return targets, records


# ===================================================================
# Burp Suite XML (proxy history export)
# ===================================================================

def import_burp_xml(xml_text: str) -> Tuple[List[Target], List[RequestRecord]]:
    """Parse Burp Suite proxy history XML.

    Burp exports ``<items>`` → ``<item>`` elements, each with
    ``<method>``, ``<url>``, ``<status>``, ``<request>``, ``<response>``
    fields.  Request/response bodies may be base64-encoded
    (``base64="true"`` attribute).

    Parameters
    ----------
    xml_text:
        Raw XML string from Burp's "Save items" export.

    Returns
    -------
    tuple
        ``(targets, records)``
    """
    targets: List[Target] = []
    records: List[RequestRecord] = []
    seen_targets: set[str] = set()

    root = ET.fromstring(xml_text)
    for item in root.iter("item"):
        url = _text(item, "url")
        method = _text(item, "method") or "GET"
        status = int(_text(item, "status") or "0")

        if not url:
            continue

        # Decode request/response (may be base64)
        req_raw = _decode_burp_field(item, "request")
        resp_raw = _decode_burp_field(item, "response")

        # Normalise line endings (XML parsers strip \r)
        req_norm = req_raw.replace("\r\n", "\n")
        resp_norm = resp_raw.replace("\r\n", "\n")

        # Parse headers from raw request
        req_headers = _parse_raw_headers(req_raw)
        resp_headers = _parse_raw_headers(resp_raw)

        # Request body: everything after blank line separator
        body: Optional[str] = None
        if "\n\n" in req_norm:
            body = req_norm.split("\n\n", 1)[1] or None

        # Response body preview
        resp_body = ""
        if "\n\n" in resp_norm:
            resp_body = resp_norm.split("\n\n", 1)[1][:500]

        # Timestamp
        ts_str = _text(item, "time")
        try:
            ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now(timezone.utc)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        records.append(RequestRecord(
            method=method,
            url=url,
            status_code=status,
            request_headers=req_headers,
            response_headers=resp_headers,
            timestamp=ts,
            request_body=body,
            response_body_preview=resp_body,
        ))

        key = f"{method}:{url}"
        if key not in seen_targets:
            seen_targets.add(key)
            targets.append(Target(url=url, method=method, headers=req_headers))

    return targets, records


# ===================================================================
# OWASP ZAP JSON (message export)
# ===================================================================

def import_zap_json(data: List[Dict[str, Any]]) -> Tuple[List[Target], List[RequestRecord]]:
    """Parse OWASP ZAP message export (JSON array of message objects).

    ZAP exports an array of objects with ``requestHeader``,
    ``requestBody``, ``responseHeader``, ``responseBody``, ``method``,
    ``url``, ``statusCode``, ``timestamp`` fields.

    Parameters
    ----------
    data:
        Parsed JSON array of ZAP message dicts.

    Returns
    -------
    tuple
        ``(targets, records)``
    """
    targets: List[Target] = []
    records: List[RequestRecord] = []
    seen_targets: set[str] = set()

    for msg in data:
        url = msg.get("url", "") or msg.get("uri", "")
        method = msg.get("method", "GET")
        status = msg.get("statusCode", 0) or msg.get("responseStatusCode", 0)

        if not url:
            continue

        req_headers = _parse_raw_headers(msg.get("requestHeader", ""))
        resp_headers = _parse_raw_headers(msg.get("responseHeader", ""))
        body = msg.get("requestBody") or None
        resp_body = (msg.get("responseBody", "") or "")[:500]

        ts_raw = msg.get("timestamp", 0)
        if isinstance(ts_raw, (int, float)) and ts_raw > 0:
            ts = datetime.fromtimestamp(ts_raw / 1000, tz=timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        records.append(RequestRecord(
            method=method,
            url=url,
            status_code=status,
            request_headers=req_headers,
            response_headers=resp_headers,
            timestamp=ts,
            request_body=body,
            response_body_preview=resp_body,
        ))

        key = f"{method}:{url}"
        if key not in seen_targets:
            seen_targets.add(key)
            targets.append(Target(url=url, method=method, headers=req_headers))

    return targets, records


# ===================================================================
# Helpers
# ===================================================================

def _parse_query(url: str) -> List[Dict[str, str]]:
    """Extract query-string pairs as HAR queryString objects."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    pairs: List[Dict[str, str]] = []
    for part in parsed.query.split("&"):
        if "=" in part:
            name, value = part.split("=", 1)
            pairs.append({"name": name, "value": value})
        else:
            pairs.append({"name": part, "value": ""})
    return pairs


def _text(element: ET.Element, tag: str) -> str:
    """Get text content of a child element, or empty string."""
    child = element.find(tag)
    return (child.text or "") if child is not None else ""


def _decode_burp_field(item: ET.Element, tag: str) -> str:
    """Decode a Burp XML field that may be base64-encoded."""
    child = item.find(tag)
    if child is None:
        return ""
    text = child.text or ""
    if child.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _parse_raw_headers(raw: str) -> Dict[str, str]:
    """Parse raw HTTP header block into a dict.

    Handles both ``Header: Value`` lines and the initial request/status line.
    Supports both ``\\r\\n`` and ``\\n`` line endings (XML parsers
    normalise CR-LF to LF).
    """
    headers: Dict[str, str] = {}
    # Normalise to \n so the parser works regardless of line-ending style.
    normalised = raw.replace("\r\n", "\n")
    for line in normalised.split("\n"):
        if not line:
            break
        if ": " in line and not line.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                                                  "PATCH ", "HEAD ", "OPTIONS ",
                                                  "HTTP/")):
            name, value = line.split(": ", 1)
            headers[name] = value
    return headers
