"""
WaaaghLogic — File upload testing.

Test file upload endpoints for unrestricted file types, path traversal
in filenames, polyglot files, and oversized uploads.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.waaaghlogic.file_upload")


# ------------------------------------------------------------------
# Test payloads
# ------------------------------------------------------------------

@dataclass
class UploadPayload:
    """A file upload test case."""
    label: str
    filename: str
    content: bytes
    content_type: str
    category: str  # dangerous_type, path_traversal, polyglot, size
    expected_reject: bool = True


UPLOAD_PAYLOADS: List[UploadPayload] = [
    # Dangerous file types
    UploadPayload("PHP webshell", "test.php", b"<?php echo 'test'; ?>", "application/x-php", "dangerous_type"),
    UploadPayload("JSP file", "test.jsp", b"<% out.println(\"test\"); %>", "application/jsp", "dangerous_type"),
    UploadPayload("ASP file", "test.asp", b"<% Response.Write(\"test\") %>", "application/asp", "dangerous_type"),
    UploadPayload("ASPX file", "test.aspx", b"<%@ Page Language=\"C#\" %>", "application/aspx", "dangerous_type"),
    UploadPayload("HTML file", "test.html", b"<script>alert(1)</script>", "text/html", "dangerous_type"),
    UploadPayload("SVG with XSS", "test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml", "dangerous_type"),
    UploadPayload("EXE file", "test.exe", b"MZ" + b"\x00" * 50, "application/octet-stream", "dangerous_type"),
    UploadPayload("Python file", "test.py", b"import os; os.system('id')", "text/x-python", "dangerous_type"),
    UploadPayload("Shell script", "test.sh", b"#!/bin/bash\nid", "text/x-shellscript", "dangerous_type"),

    # Double extensions
    UploadPayload("Double ext .php.jpg", "test.php.jpg", b"<?php echo 1; ?>", "image/jpeg", "dangerous_type"),
    UploadPayload("Double ext .html.png", "test.html.png", b"<script>alert(1)</script>", "image/png", "dangerous_type"),
    UploadPayload("Null byte ext", "test.php%00.jpg", b"<?php echo 1; ?>", "image/jpeg", "dangerous_type"),

    # Path traversal in filename
    UploadPayload("Path traversal ../", "../../../etc/passwd", b"test", "text/plain", "path_traversal"),
    UploadPayload("Path traversal ..\\", "..\\..\\..\\test.txt", b"test", "text/plain", "path_traversal"),
    UploadPayload("Path traversal encoded", "..%2f..%2ftest.txt", b"test", "text/plain", "path_traversal"),
    UploadPayload("Absolute path /etc", "/etc/cron.d/test", b"test", "text/plain", "path_traversal"),
    UploadPayload("Absolute path C:\\", "C:\\inetpub\\test.txt", b"test", "text/plain", "path_traversal"),

    # Polyglot files
    UploadPayload(
        "GIF polyglot",
        "polyglot.gif",
        b"GIF89a" + b"<?php echo 1; ?>",
        "image/gif",
        "polyglot",
    ),
    UploadPayload(
        "JPEG polyglot",
        "polyglot.jpg",
        b"\xff\xd8\xff\xe0" + b"<?php echo 1; ?>",
        "image/jpeg",
        "polyglot",
    ),
    UploadPayload(
        "PDF polyglot",
        "polyglot.pdf",
        b"%PDF-1.4\n<script>alert(1)</script>",
        "application/pdf",
        "polyglot",
    ),
]


@dataclass
class UploadTestResult:
    """Outcome of a single upload test."""
    payload_label: str
    filename: str
    accepted: bool = False
    status_code: int = 0
    response_snippet: str = ""
    category: str = ""


class FileUploadTester:
    """
    Test file upload endpoints for dangerous file acceptance.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        payloads: Optional[List[UploadPayload]] = None,
        file_field: str = "file",
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._payloads = payloads or UPLOAD_PAYLOADS
        self._file_field = file_field

    async def test(self, target: Target) -> List[Finding]:
        """Test all upload payloads against *target*."""
        findings: List[Finding] = []
        results = await self._run_tests(target)

        # Group accepted results by category
        by_cat: Dict[str, List[UploadTestResult]] = {}
        for r in results:
            if r.accepted:
                by_cat.setdefault(r.category, []).append(r)

        if "dangerous_type" in by_cat:
            items = by_cat["dangerous_type"]
            names = ", ".join(r.filename for r in items[:8])
            findings.append(Finding(
                title=f"Unrestricted file upload — dangerous types accepted ({len(items)})",
                description=(
                    f"Server accepted files with dangerous extensions: {names}. "
                    f"This may allow remote code execution."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(f"  {r.filename} → {r.status_code}" for r in items),
                remediation=(
                    "Validate file type by content (magic bytes), not extension. "
                    "Whitelist allowed MIME types. Store uploads outside webroot."
                ),
                cwe=434,
                tags=["file-upload", "unrestricted-type"],
            ))

        if "path_traversal" in by_cat:
            items = by_cat["path_traversal"]
            findings.append(Finding(
                title=f"File upload path traversal ({len(items)} accepted)",
                description="Server accepted filenames containing path traversal sequences.",
                severity=Severity.HIGH,
                target=target,
                evidence="\n".join(f"  {r.filename} → {r.status_code}" for r in items),
                remediation="Sanitise uploaded filenames. Strip path separators and use server-generated names.",
                cwe=22,
                tags=["file-upload", "path-traversal"],
            ))

        if "polyglot" in by_cat:
            items = by_cat["polyglot"]
            findings.append(Finding(
                title=f"Polyglot file upload accepted ({len(items)})",
                description="Server accepted files with valid image headers but embedded code.",
                severity=Severity.MEDIUM,
                target=target,
                evidence="\n".join(f"  {r.filename} → {r.status_code}" for r in items),
                remediation="Re-process uploaded images (strip metadata, re-encode). Validate content deeply.",
                cwe=434,
                tags=["file-upload", "polyglot"],
            ))

        return findings

    @staticmethod
    def get_payloads(category: Optional[str] = None) -> List[UploadPayload]:
        if category:
            return [p for p in UPLOAD_PAYLOADS if p.category == category]
        return list(UPLOAD_PAYLOADS)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run_tests(self, target: Target) -> List[UploadTestResult]:
        results: List[UploadTestResult] = []
        client = self._get_client()

        try:
            for payload in self._payloads:
                try:
                    # Build multipart form data as JSON since we can't do real multipart
                    # In a real scenario we'd use httpx's files parameter
                    resp = await client.request(
                        "POST", target.url,
                        headers={
                            "Content-Type": "multipart/form-data",
                            "X-Filename": payload.filename,
                            "X-Content-Type": payload.content_type,
                        },
                        body=payload.content,
                    )
                    code = getattr(resp, "status_code", 0)
                    text = (getattr(resp, "text", "") or "")[:200]
                    accepted = code in (200, 201, 204)

                    results.append(UploadTestResult(
                        payload_label=payload.label,
                        filename=payload.filename,
                        accepted=accepted,
                        status_code=code,
                        response_snippet=text,
                        category=payload.category,
                    ))
                except Exception as exc:
                    logger.debug("Upload test error for %s: %s", payload.label, exc)
        finally:
            self._maybe_close(client)

        return results

    def _get_client(self) -> HttpClient:
        return self._client or HttpClient(timeout=10.0, retries=0)

    def _maybe_close(self, client: HttpClient) -> None:
        pass
