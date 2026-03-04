"""
GrotAssault — main module entry-point.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from krumpa.core import BaseModule, Finding, ScanContext, Target
from krumpa.core.http_client import HttpClient
from krumpa.grotassault.fuzzer import Fuzzer, FuzzTarget
from krumpa.grotassault.mutator import Mutator, MutationStrategy
from krumpa.grotassault.xxe_payloads import XxeChecker
from krumpa.grotassault.ssrf_payloads import SsrfChecker
from krumpa.grotassault.nosql_payloads import NoSqlChecker
from krumpa.grotassault.crlf_payloads import CrlfChecker
from krumpa.grotassault.smuggling import HttpSmugglingChecker
from krumpa.grotassault.blind_oob import BlindOobDetector
from krumpa.grotassault.deserialization import DeserializationChecker
from krumpa.grotassault.content_type import ContentTypeSwitcher
from krumpa.grotassault.path_traversal import PathTraversalChecker
from krumpa.grotassault.open_redirect import OpenRedirectChecker
from krumpa.grotassault.ldap_payloads import LdapChecker
from krumpa.grotassault.prototype_pollution import PrototypePollutionChecker
from krumpa.grotassault.param_pollution import ParamPollutionChecker
from krumpa.grotassault.graphql_fuzzer import GraphqlFuzzer
from krumpa.grotassault.cache_poisoning import CachePoisonChecker
from krumpa.grotassault.unicode_normalization import UnicodeNormalizationChecker
from krumpa.grotassault.content_type_fuzzer import ContentTypeAwareFuzzer
from krumpa.grotassault.response_fingerprint import ResponseFingerprinter
from krumpa.grotassault.payload_db import PayloadDB
from krumpa.grotassault.websocket_fuzzer import WebSocketFuzzer

logger = logging.getLogger("krumpa.grotassault")


class GrotAssaultModule(BaseModule):
    """Mutation fuzzing — payload generation, anomaly detection."""

    name = "GrotAssault"
    description = "Mutation Fuzzing — payload generation, boundary testing, anomaly detection"
    dependencies: List[str] = ["SneakyGits"]  # needs targets to fuzz

    def __init__(
        self,
        *,
        fuzz_targets: Optional[List[FuzzTarget]] = None,
        strategies: Optional[Sequence[MutationStrategy]] = None,
        max_payloads_per_field: int = 30,
        http_client: Optional[HttpClient] = None,
        baseline_deviation_pct: float = 200.0,
        timeout_threshold_ms: float = 5000.0,
    ) -> None:
        super().__init__()
        self._explicit_client = http_client is not None
        self._mutator = Mutator(
            strategies=strategies,
            max_payloads_per_field=max_payloads_per_field,
        )
        self._fuzzer = Fuzzer(
            http_client=http_client,
            mutator=self._mutator,
            baseline_deviation_pct=baseline_deviation_pct,
            timeout_threshold_ms=timeout_threshold_ms,
        )
        self._fuzz_targets = fuzz_targets or []
        self._xxe_checker = XxeChecker(http_client=http_client)
        self._ssrf_checker = SsrfChecker(http_client=http_client)
        self._nosql_checker = NoSqlChecker(http_client=http_client)
        self._crlf_checker = CrlfChecker(http_client=http_client)
        self._smuggling_checker = HttpSmugglingChecker(http_client=http_client)
        self._blind_oob = BlindOobDetector(http_client=http_client)
        self._deserialization = DeserializationChecker(http_client=http_client)
        self._content_type = ContentTypeSwitcher(http_client=http_client)
        self._path_traversal = PathTraversalChecker(http_client=http_client)
        self._open_redirect = OpenRedirectChecker(http_client=http_client)
        self._ldap_checker = LdapChecker(http_client=http_client)
        self._proto_pollution = PrototypePollutionChecker(http_client=http_client)
        self._param_pollution = ParamPollutionChecker(http_client=http_client)
        self._graphql_fuzzer = GraphqlFuzzer(http_client=http_client)
        self._cache_poison = CachePoisonChecker(http_client=http_client)
        self._unicode_norm = UnicodeNormalizationChecker(http_client=http_client)
        self._ct_aware_fuzzer = ContentTypeAwareFuzzer(http_client=http_client)
        self._resp_fingerprinter = ResponseFingerprinter()
        self._payload_db = PayloadDB()
        self._websocket_fuzzer = WebSocketFuzzer()

    async def setup(self, ctx: ScanContext) -> None:
        """Wire shared HTTP client into fuzzer and sub-checkers if no explicit client."""
        if ctx.http_client and not self._explicit_client:
            self._fuzzer._client = ctx.http_client
            self._fuzzer._owns_client = False
            self._xxe_checker._client = ctx.http_client
            self._xxe_checker._owns_client = False
            self._ssrf_checker._client = ctx.http_client
            self._ssrf_checker._owns_client = False
            self._nosql_checker._client = ctx.http_client
            self._nosql_checker._owns_client = False
            self._crlf_checker._client = ctx.http_client
            self._crlf_checker._owns_client = False
            self._smuggling_checker._client = ctx.http_client
            self._smuggling_checker._owns_client = False
            self._blind_oob._client = ctx.http_client
            self._blind_oob._owns_client = False
            self._deserialization._client = ctx.http_client
            self._deserialization._owns_client = False
            self._content_type._client = ctx.http_client
            self._content_type._owns_client = False
            self._path_traversal._client = ctx.http_client
            self._path_traversal._owns_client = False
            self._open_redirect._client = ctx.http_client
            self._open_redirect._owns_client = False
            self._ldap_checker._client = ctx.http_client
            self._ldap_checker._owns_client = False
            self._proto_pollution._client = ctx.http_client
            self._proto_pollution._owns_client = False
            self._param_pollution._client = ctx.http_client
            self._param_pollution._owns_client = False
            self._graphql_fuzzer._client = ctx.http_client
            self._graphql_fuzzer._owns_client = False
            self._cache_poison._client = ctx.http_client
            self._cache_poison._owns_client = False
            self._unicode_norm._client = ctx.http_client
            self._unicode_norm._owns_client = False
            self._ct_aware_fuzzer._client = ctx.http_client
            self._ct_aware_fuzzer._owns_client = False
            self._websocket_fuzzer._client = ctx.http_client
            self._websocket_fuzzer._owns_client = False

    # ------------------------------------------------------------------
    # Module lifecycle
    # ------------------------------------------------------------------

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Explicit fuzz targets
        for ft in self._fuzz_targets:
            target = self._resolve_target(ft.url, ctx)
            logger.info("Fuzzing %s %s (%d fields)", ft.method, ft.url,
                        len(ft.fuzz_fields) or len(ft.base_body or {}))
            ft_findings = await self._fuzzer.fuzz(ft, target)
            findings.extend(ft_findings)

        # 2. Auto-detect fuzzable endpoints from context
        auto_targets = self._detect_fuzzable(ctx)
        for ft in auto_targets:
            target = self._resolve_target(ft.url, ctx)
            logger.info("Auto-fuzzing %s %s", ft.method, ft.url)
            ft_findings = await self._fuzzer.fuzz(ft, target)
            findings.extend(ft_findings)

        # 3. XXE checks on XML-accepting endpoints
        for target in ctx.targets:
            ct = target.headers.get("Content-Type", "")
            if "xml" in ct.lower() or target.method.upper() in ("POST", "PUT", "PATCH"):
                logger.info("XXE testing %s %s", target.method, target.url)
                xxe_findings = await self._xxe_checker.check(target)
                findings.extend(xxe_findings)

        # 4. SSRF checks on endpoints with URL-type parameters
        for target in ctx.targets:
            ssrf_findings = await self._ssrf_checker.check(target)
            if ssrf_findings:
                logger.info("SSRF findings on %s", target.url)
                findings.extend(ssrf_findings)

        # 5. NoSQL injection checks on targets with bodies
        for target in ctx.targets:
            if target.method.upper() in ("POST", "PUT", "PATCH") or "?" in target.url:
                logger.info("NoSQL injection testing %s %s", target.method, target.url)
                nosql_findings = await self._nosql_checker.check(target)
                findings.extend(nosql_findings)

        # 6. CRLF / header injection checks
        for target in ctx.targets:
            logger.info("CRLF injection testing %s", target.url)
            crlf_findings = await self._crlf_checker.check(target)
            findings.extend(crlf_findings)

        # 7. HTTP request smuggling checks
        for target in ctx.targets:
            logger.info("HTTP smuggling testing %s", target.url)
            smuggling_findings = await self._smuggling_checker.check(target)
            findings.extend(smuggling_findings)

        # 8. Blind OOB injection probes
        for target in ctx.targets:
            for vuln_type in ("sqli", "xxe", "ssrf"):
                payloads = self._blind_oob.build_payloads(vuln_type)
                if payloads:
                    oob_findings = await self._blind_oob.inject_and_poll(target, payloads)
                    findings.extend(oob_findings)

        # 9. Deserialization checks on endpoints with bodies
        for target in ctx.targets:
            if target.method.upper() in ("POST", "PUT", "PATCH"):
                deser_findings = await self._deserialization.check(target)
                findings.extend(deser_findings)

        # 10. Content-type confusion checks
        for target in ctx.targets:
            if target.method.upper() in ("POST", "PUT", "PATCH"):
                ct_findings = await self._content_type.check(target)
                findings.extend(ct_findings)

        # 11. Path traversal checks
        for target in ctx.targets:
            trav_findings = await self._path_traversal.check(target)
            findings.extend(trav_findings)

        # 12. Open redirect checks on GET endpoints
        for target in ctx.targets:
            if target.method.upper() == "GET":
                redir_findings = await self._open_redirect.check(target)
                findings.extend(redir_findings)

        # 13. LDAP injection checks on endpoints with search/query semantics
        for target in ctx.targets:
            if target.method.upper() in ("POST", "GET") and (
                "?" in target.url or target.body
            ):
                logger.info("LDAP injection testing %s %s", target.method, target.url)
                ldap_findings = await self._ldap_checker.check(target)
                findings.extend(ldap_findings)

        # 14. Prototype pollution checks on JSON-accepting endpoints
        for target in ctx.targets:
            ct = (target.headers or {}).get("Content-Type", "")
            if "json" in ct.lower() or target.method.upper() in ("POST", "PUT", "PATCH"):
                logger.info("Prototype pollution testing %s %s", target.method, target.url)
                pp_findings = await self._proto_pollution.check(target)
                findings.extend(pp_findings)

        # 15. HTTP parameter pollution checks
        for target in ctx.targets:
            logger.info("HTTP parameter pollution testing %s", target.url)
            hpp_findings = await self._param_pollution.check(target)
            findings.extend(hpp_findings)

        # 16. GraphQL fuzzing — depth bombs, alias abuse, batched mutations
        for target in ctx.targets:
            if any(kw in target.url.lower() for kw in ("/graphql", "/gql", "/query")):
                logger.info("GraphQL fuzzing %s", target.url)
                gql_findings = await self._graphql_fuzzer.check(target)
                findings.extend(gql_findings)

        # 17. Cache poisoning — unkeyed headers, query string poisoning
        for target in ctx.targets:
            if target.method.upper() == "GET":
                logger.info("Cache poisoning testing %s", target.url)
                cache_findings = await self._cache_poison.check(target)
                findings.extend(cache_findings)

        # 18. Unicode normalization attacks
        for target in ctx.targets:
            logger.info("Unicode normalization testing %s", target.url)
            uni_findings = await self._unicode_norm.check(target)
            findings.extend(uni_findings)

        # 19. Content-type-aware body fuzzing — GraphQL, SOAP, YAML etc.
        for target in ctx.targets:
            if target.method.upper() in ("POST", "PUT", "PATCH"):
                logger.info("Content-type-aware fuzzing %s %s", target.method, target.url)
                ct_findings = await self._ct_aware_fuzzer.check(target)
                findings.extend(ct_findings)

        # 20. Response fingerprinting — cluster by similarity
        if ctx.targets:
            logger.info("Response fingerprinting across %d targets", len(ctx.targets))
            fp_findings = self._resp_fingerprinter.analyze(ctx.targets)
            findings.extend(fp_findings)

        # 21. WebSocket fuzzing — message injection, CSWSH
        for target in ctx.targets:
            logger.info("WebSocket fuzzing %s", target.url)
            ws_findings = await self._websocket_fuzzer.check(target)
            findings.extend(ws_findings)

        for f in findings:
            self.add_finding(f)

        logger.info("GrotAssault complete — %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target(url: str, ctx: ScanContext) -> Target:
        """Return the matching Target from context, or synthesise one."""
        for t in ctx.targets:
            if t.url == url:
                return t
        return Target(url=url)

    @staticmethod
    def _detect_fuzzable(ctx: ScanContext) -> List[FuzzTarget]:
        """
        Heuristic: build FuzzTargets from context targets that use
        POST/PUT/PATCH and have body content or query parameters.
        """
        results: List[FuzzTarget] = []
        seen: set = set()
        fuzzable_methods = ("POST", "PUT", "PATCH")

        for t in ctx.targets:
            if t.method.upper() not in fuzzable_methods:
                continue
            key = (t.url, t.method.upper())
            if key in seen:
                continue
            seen.add(key)

            # Try to build a body dict from metadata or raw body
            base_body = _extract_body(t)
            if not base_body:
                continue

            results.append(FuzzTarget(
                url=t.url,
                method=t.method.upper(),
                base_body=base_body,
                base_headers=t.headers or None,
            ))

        return results


def _extract_body(target: Target) -> Optional[Dict[str, Any]]:
    """Best-effort extraction of a JSON body dict from a Target."""
    # Check metadata first (modules may store parsed bodies there)
    if "body_json" in target.metadata:
        body = target.metadata["body_json"]
        if isinstance(body, dict):
            return body

    # Try parsing the raw body field
    if target.body:
        import json
        try:
            parsed = json.loads(target.body)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    # Check query-string parameters in the URL
    parsed_url = urlparse(target.url)
    if parsed_url.query:
        from urllib.parse import parse_qs
        qs = parse_qs(parsed_url.query)
        if qs:
            return {k: v[0] if len(v) == 1 else v for k, v in qs.items()}

    return None
