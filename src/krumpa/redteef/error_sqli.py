"""
RedTeef — Error-based SQL injection confirmer.

Detects SQL injection by analysing HTTP responses for database-specific
error strings.  Error-based SQLi is the most straightforward class to
confirm because the DBMS leaks recognisable error messages.

Covers:
  - MySQL / MariaDB
  - PostgreSQL
  - Microsoft SQL Server
  - Oracle
  - SQLite
  - IBM DB2

References:
  - CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  - OWASP Testing Guide: OTG-INPVAL-005
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.error_sqli")


# ------------------------------------------------------------------
# Database error signatures
# ------------------------------------------------------------------

@dataclass(frozen=True)
class DbErrorSignature:
    """A DBMS-specific error pattern."""
    dbms: str
    pattern: re.Pattern[str]
    description: str


_ERROR_SIGNATURES: List[DbErrorSignature] = [
    # MySQL / MariaDB
    DbErrorSignature("mysql", re.compile(r"You have an error in your SQL syntax", re.I), "MySQL syntax error"),
    DbErrorSignature("mysql", re.compile(r"Warning:.*mysql_", re.I), "PHP mysql_ function error"),
    DbErrorSignature("mysql", re.compile(r"MySqlException", re.I), ".NET MySQL exception"),
    DbErrorSignature("mysql", re.compile(r"com\.mysql\.jdbc", re.I), "Java MySQL connector error"),
    DbErrorSignature("mysql", re.compile(r"SQLSTATE\[42000\]", re.I), "MySQL PDO error"),
    DbErrorSignature("mysql", re.compile(r"Unknown column '.*' in '.*'", re.I), "MySQL unknown column"),

    # PostgreSQL
    DbErrorSignature("postgresql", re.compile(r"ERROR:\s+syntax error at or near", re.I), "PostgreSQL syntax error"),
    DbErrorSignature("postgresql", re.compile(r"pg_query\(\)", re.I), "PHP pg_query error"),
    DbErrorSignature("postgresql", re.compile(r"PSQLException", re.I), "Java PostgreSQL exception"),
    DbErrorSignature("postgresql", re.compile(r"SQLSTATE\[42601\]", re.I), "PostgreSQL PDO error"),
    DbErrorSignature("postgresql", re.compile(r"unterminated quoted string", re.I), "PostgreSQL unterminated string"),

    # Microsoft SQL Server
    DbErrorSignature("mssql", re.compile(r"Unclosed quotation mark after", re.I), "MSSQL unclosed quote"),
    DbErrorSignature("mssql", re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "MSSQL OLE DB error"),
    DbErrorSignature("mssql", re.compile(r"SqlException", re.I), ".NET SQL exception"),
    DbErrorSignature("mssql", re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.I), "MSSQL ODBC error"),
    DbErrorSignature("mssql", re.compile(r"Incorrect syntax near", re.I), "MSSQL syntax error"),
    DbErrorSignature("mssql", re.compile(r"SQLServer JDBC Driver", re.I), "Java MSSQL JDBC error"),

    # Oracle
    DbErrorSignature("oracle", re.compile(r"ORA-\d{4,5}", re.I), "Oracle error code"),
    DbErrorSignature("oracle", re.compile(r"PLS-\d{4,5}", re.I), "Oracle PL/SQL error"),
    DbErrorSignature("oracle", re.compile(r"oracle\.jdbc", re.I), "Java Oracle JDBC error"),
    DbErrorSignature("oracle", re.compile(r"quoted string not properly terminated", re.I), "Oracle quoted string"),

    # SQLite
    DbErrorSignature("sqlite", re.compile(r"SQLite3::query\(\)", re.I), "PHP SQLite error"),
    DbErrorSignature("sqlite", re.compile(r"SQLITE_ERROR", re.I), "SQLite error code"),
    DbErrorSignature("sqlite", re.compile(r"sqlite3\.OperationalError", re.I), "Python SQLite error"),
    DbErrorSignature("sqlite", re.compile(r"near \".*\": syntax error", re.I), "SQLite syntax error"),

    # IBM DB2
    DbErrorSignature("db2", re.compile(r"CLI Driver.*DB2", re.I), "DB2 CLI error"),
    DbErrorSignature("db2", re.compile(r"SQLCODE=-\d+", re.I), "DB2 SQL code"),
    DbErrorSignature("db2", re.compile(r"db2_\w+\(\)", re.I), "PHP DB2 function error"),
]

# Injection probes designed to trigger error responses
_ERROR_PROBES: List[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "1' AND '1'='2' --",
    "1;SELECT 1--",
    "' UNION SELECT NULL--",
    "1)) OR ((1=1",
    "\\",
]


class ErrorSqliConfirmer:
    """Confirm SQL injection via database error extraction."""

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def confirm(
        self,
        target: Target,
        *,
        inject_field: str = "",
    ) -> List[Finding]:
        """Inject error-triggering payloads and scan responses for DB errors."""
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=10.0, retries=0)

        try:
            for probe in _ERROR_PROBES:
                resp_text = await self._inject_probe(client, target, probe, inject_field)
                if resp_text is None:
                    continue

                matches = self._scan_for_errors(resp_text)
                if matches:
                    dbms_set = {m.dbms for m in matches}
                    findings.append(Finding(
                        title=f"Error-based SQL injection on {target.url}",
                        description=(
                            f"Injecting '{probe}' into {inject_field or 'the request'} "
                            f"triggers database error messages from: {', '.join(sorted(dbms_set))}. "
                            f"This confirms SQL injection vulnerability."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence="\n".join(
                            f"[{m.dbms}] {m.description}: {m.pattern.pattern}"
                            for m in matches[:5]
                        ),
                        remediation=(
                            "Use parameterised queries / prepared statements. "
                            "Never concatenate user input into SQL strings. "
                            "Suppress detailed database error messages in production."
                        ),
                        cwe=89,
                        tags=["sqli", "error-based", "confirmed", "redteef"],
                    ))
                    break  # one confirmed finding is enough

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    async def _inject_probe(
        self,
        client: HttpClient,
        target: Target,
        probe: str,
        field: str,
    ) -> Optional[str]:
        """Inject *probe* into the target and return the response body."""
        try:
            if target.method.upper() in ("POST", "PUT", "PATCH") and field:
                body = f"{field}={probe}"
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                resp = await client.request(
                    target.method, target.url,
                    body=body, headers=headers,
                )
            else:
                # Inject through query string
                separator = "&" if "?" in target.url else "?"
                param_name = field or "id"
                url = f"{target.url}{separator}{param_name}={probe}"
                resp = await client.get(url)

            return resp.text

        except (httpx.HTTPError, OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Error scanning
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_for_errors(text: str) -> List[DbErrorSignature]:
        """Scan response text for database-specific error patterns."""
        matches: List[DbErrorSignature] = []
        for sig in _ERROR_SIGNATURES:
            if sig.pattern.search(text):
                matches.append(sig)
        return matches

    @staticmethod
    def detect_dbms(text: str) -> Optional[str]:
        """Best-effort DBMS detection from an error response."""
        for sig in _ERROR_SIGNATURES:
            if sig.pattern.search(text):
                return sig.dbms
        return None
