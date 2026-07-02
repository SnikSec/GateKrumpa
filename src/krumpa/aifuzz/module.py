"""
AiFuzz — AI/LLM attack surface testing module.

Targets standard HTTPS endpoints that host LLM APIs (OpenAI-compatible,
Anthropic, Ollama, Gradio, Triton, LangServe, etc.).  AI endpoints are
identified either:
  - Explicitly: targets whose URL fingerprint signals (from ScanContext) match
    an AI infrastructure technology
  - Via metadata: ``target.metadata["ai_api_key"]`` or ``target.metadata["ai_model"]``
    are set

Uses the shared :class:`~krumpa.core.http_client.HttpClient` for all requests.
No external ML libraries required for basic operation.
"""

from __future__ import annotations

import logging
from typing import List

from krumpa.core import BaseModule, Finding, ScanContext, Target, TargetType

logger = logging.getLogger("krumpa.aifuzz")

# Technology names from fingerprint_db/fingerprint.py that indicate an AI endpoint
_AI_TECH_SIGNALS = frozenset({
    "Gradio", "Streamlit", "FastAPI", "Triton Inference Server",
    "NVIDIA NIM", "Ollama", "LangServe", "OpenAI-compatible API",
    "Hugging Face Spaces",
})


class AiFuzzModule(BaseModule):
    """AI/LLM attack surface — prompt injection, jailbreaking, token smuggling,
    system prompt extraction, guardrail bypass, indirect injection, and response analysis."""

    name = "aifuzz"
    description = (
        "AI/LLM attack surface testing — prompt injection, jailbreaking, "
        "token smuggling, system prompt extraction, guardrail bypass, "
        "indirect/RAG injection, and sensitive data leakage detection"
    )
    dependencies: List[str] = ["sneakygits"]  # needs fingerprint signals

    def __init__(self) -> None:
        super().__init__()

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        ai_targets = self._identify_ai_targets(ctx)
        if not ai_targets:
            logger.debug("No AI endpoint targets found — aifuzz skipped")
            return []

        from krumpa.aifuzz.prompt_injector import PromptInjector
        from krumpa.aifuzz.jailbreak_tester import JailbreakTester
        from krumpa.aifuzz.token_smuggler import TokenSmuggler
        from krumpa.aifuzz.system_prompt_extractor import SystemPromptExtractor
        from krumpa.aifuzz.guardrail_bypass import GuardrailBypass
        from krumpa.aifuzz.indirect_injector import IndirectInjector
        from krumpa.aifuzz.response_analyzer import ResponseAnalyzer

        client = ctx.http_client
        analyzers = [
            PromptInjector(http_client=client),
            JailbreakTester(http_client=client),
            TokenSmuggler(http_client=client),
            SystemPromptExtractor(http_client=client),
            GuardrailBypass(http_client=client),
            IndirectInjector(http_client=client),
        ]
        response_analyzer = ResponseAnalyzer()

        for target in ai_targets:
            session = _AiSession.from_target(target)
            logger.info("AiFuzz: testing %s (model=%s)", target.url, session.model or "unknown")

            all_responses: List[str] = []
            for analyzer in analyzers:
                try:
                    new_findings, responses = await analyzer.analyze(target, session, ctx)
                    findings.extend(new_findings)
                    all_responses.extend(responses)
                except Exception as exc:
                    logger.warning("%s failed on %s: %s", type(analyzer).__name__, target.url, exc)

            # Run response analyzer over all collected LLM outputs
            findings.extend(response_analyzer.analyze(all_responses, target))

        for f in findings:
            self.add_finding(f)
        return findings

    @staticmethod
    def _identify_ai_targets(ctx: ScanContext) -> List[Target]:
        """Return targets that appear to host AI/LLM endpoints."""
        ai_targets: List[Target] = []
        fingerprints: dict = ctx.metadata.get("fingerprints", {})

        for target in ctx.targets:
            # Explicit metadata flag
            if target.metadata.get("ai_api_key") or target.metadata.get("ai_model"):
                ai_targets.append(target)
                continue
            # Fingerprint signal
            fp = fingerprints.get(target.url)
            if fp is not None:
                techs = set(getattr(fp, "technologies", []))
                if techs & _AI_TECH_SIGNALS:
                    ai_targets.append(target)

        return ai_targets


class _AiSession:
    """Thin wrapper holding per-target AI API configuration."""

    __slots__ = ("endpoint", "api_key", "model", "provider", "headers")

    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        model: str = "",
        provider: str = "",
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.headers: dict = {}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    @classmethod
    def from_target(cls, target: Target) -> "_AiSession":
        return cls(
            endpoint=target.url,
            api_key=target.metadata.get("ai_api_key", ""),
            model=target.metadata.get("ai_model", ""),
            provider=target.metadata.get("ai_provider", ""),
        )
