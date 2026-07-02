"""
ModelHunt — AI model analysis, extraction, and supply chain auditing module.

Depends on ``aifuzz`` (inherits the identified AI endpoint targets and any
session/model metadata collected during AI attack surface testing).

Sub-analyzers:
  - :class:`~krumpa.modelhunt.model_extractor.ModelExtractor`       — systematic output probing for model fingerprinting
  - :class:`~krumpa.modelhunt.membership_inference.MembershipInferenceProber`  — training data memorisation detection
  - :class:`~krumpa.modelhunt.pii_extractor.PiiExtractor`           — targeted prompts to surface memorised PII
  - :class:`~krumpa.modelhunt.vector_db_scanner.VectorDbScanner`    — exposed vector DB endpoint discovery
  - :class:`~krumpa.modelhunt.supply_chain_auditor.SupplyChainAuditor` — HuggingFace/PyPI supply chain risks

The ART (Adversarial Robustness Toolbox) integration is optional:
install ``gatekrumpa[art]`` to activate text perturbation attacks.
"""

from __future__ import annotations

import logging
from typing import List

from krumpa.core import BaseModule, Finding, ScanContext, Target

logger = logging.getLogger("krumpa.modelhunt")

# Technology signals that indicate a model inference endpoint (from aifuzz / fingerprinting)
_AI_TECH_SIGNALS = frozenset({
    "Gradio", "Streamlit", "FastAPI", "Triton Inference Server",
    "NVIDIA NIM", "Ollama", "LangServe", "OpenAI-compatible API",
    "Hugging Face Spaces",
})


class ModelHuntModule(BaseModule):
    """Model analysis and supply chain auditing — extraction, membership inference,
    PII leakage, vector DB exposure, and dependency/model supply chain risks."""

    name = "modelhunt"
    description = (
        "AI model analysis — systematic extraction probing, training data "
        "membership inference, PII leakage, vector DB exposure, and "
        "supply chain auditing (HuggingFace, PyPI)"
    )
    dependencies: List[str] = ["aifuzz"]

    def __init__(self) -> None:
        super().__init__()

    async def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []

        ai_targets = _identify_ai_targets(ctx)
        if not ai_targets:
            logger.debug("No AI endpoint targets found — modelhunt skipped")
            return []

        from krumpa.modelhunt.model_extractor import ModelExtractor
        from krumpa.modelhunt.membership_inference import MembershipInferenceProber
        from krumpa.modelhunt.pii_extractor import PiiExtractor
        from krumpa.modelhunt.vector_db_scanner import VectorDbScanner
        from krumpa.modelhunt.supply_chain_auditor import SupplyChainAuditor

        client = ctx.http_client

        # Analyzers that test against AI API endpoints
        api_analyzers = [
            ModelExtractor(http_client=client),
            MembershipInferenceProber(http_client=client),
            PiiExtractor(http_client=client),
        ]

        for target in ai_targets:
            session = _AiSession.from_target(target)
            logger.info("ModelHunt: analysing %s (model=%s)", target.url, session.model or "unknown")

            for analyzer in api_analyzers:
                try:
                    new_findings = await analyzer.analyze(target, session, ctx)
                    findings.extend(new_findings)
                except Exception as exc:
                    logger.warning("%s failed on %s: %s", type(analyzer).__name__, target.url, exc)

        # Vector DB scanner — probes all web targets for exposed vector DB endpoints
        vdb_scanner = VectorDbScanner(http_client=client)
        for target in ctx.targets:
            try:
                findings.extend(await vdb_scanner.scan(target))
            except Exception as exc:
                logger.warning("VectorDbScanner failed on %s: %s", target.url, exc)

        # Supply chain auditor — uses target metadata (model_id, requirements path, etc.)
        supply_auditor = SupplyChainAuditor(http_client=client)
        for target in ai_targets:
            try:
                findings.extend(await supply_auditor.audit(target, ctx))
            except Exception as exc:
                logger.warning("SupplyChainAuditor failed on %s: %s", target.url, exc)

        for f in findings:
            self.add_finding(f)
        return findings


def _identify_ai_targets(ctx: ScanContext) -> List[Target]:
    """Return targets that appear to host AI/LLM endpoints (reuses aifuzz logic)."""
    fingerprints: dict = ctx.metadata.get("fingerprints", {})
    ai_targets: List[Target] = []
    for target in ctx.targets:
        if target.metadata.get("ai_api_key") or target.metadata.get("ai_model"):
            ai_targets.append(target)
            continue
        fp = fingerprints.get(target.url)
        if fp is not None:
            techs = set(getattr(fp, "technologies", []))
            if techs & _AI_TECH_SIGNALS:
                ai_targets.append(target)
    return ai_targets


class _AiSession:
    """Thin AI API session wrapper (mirrors aifuzz._AiSession)."""

    __slots__ = ("endpoint", "api_key", "model", "provider", "headers")

    def __init__(self, endpoint: str, api_key: str = "", model: str = "", provider: str = "") -> None:
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
