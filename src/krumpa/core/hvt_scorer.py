"""
GateKrumpa core — High-Value Target (HVT) scorer.

Two-phase prioritisation of scan targets:

**Phase 1 (always active)** — fast pattern matching without any external
dependencies.  Signals are extracted from fingerprint results, finding tags,
and target metadata already collected during the scan.

**Phase 2 (optional, requires ``[ai]`` extra)** — AutoGen-assisted contextual
reasoning that incorporates OSINT signals and business context into scoring.
Falls back to Phase 1 scores if AutoGen is not installed.

Scores are stored in ``ScanContext.metadata["hvt_scores"]`` as a list of
:class:`TargetScore` objects sorted highest-score first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from krumpa.core import ScanContext, Severity, Target

logger = logging.getLogger("krumpa.core.hvt_scorer")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class TargetScore:
    """Scoring result for a single target.

    Attributes
    ----------
    target:
        The scored :class:`Target`.
    score:
        Normalised priority score from 0.0 (lowest) to 1.0 (highest).
    priority:
        Human-readable priority bucket: ``"critical"``, ``"high"``,
        ``"medium"``, or ``"low"``.
    signals:
        Human-readable list of signals that contributed to this score.
    """
    target: Target
    score: float = 0.0
    priority: str = "low"
    signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target.url,
            "score": round(self.score, 3),
            "priority": self.priority,
            "signals": self.signals,
        }


# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------

# Fingerprint technology names that indicate high-value targets
_PAYMENT_SIGNALS = frozenset({"Stripe", "Braintree", "PayPal", "Adyen"})
_AUTH_SIGNALS = frozenset({"AWS Cognito", "Okta", "Auth0", "Keycloak", "SAML"})
_AI_SIGNALS = frozenset({
    "Gradio", "Streamlit", "FastAPI", "Triton Inference Server",
    "NVIDIA NIM", "Ollama", "LangServe", "OpenAI-compatible API",
})
_DATA_SIGNALS = frozenset({"Elasticsearch", "Kibana", "OpenSearch Dashboards"})
_ADMIN_SIGNALS = frozenset({"Jenkins", "Grafana", "Prometheus", "vCenter UI"})

# Finding tag patterns that add score weight
_HIGH_IMPACT_TAGS = frozenset({
    "privilege-escalation", "credential-theft", "data-exfiltration",
    "attack-chain", "prompt-injection", "ssrf", "rce-risk",
    "public-access", "unauthenticated", "imds",
})

# URL keyword patterns that suggest high-value targets
_URL_KEYWORDS: List[Tuple[str, float, str]] = [
    ("payment", 0.4, "Payment processing endpoint"),
    ("billing", 0.35, "Billing endpoint"),
    ("checkout", 0.3, "Checkout endpoint"),
    ("admin", 0.25, "Admin interface"),
    ("internal", 0.2, "Internal service"),
    ("api", 0.15, "API endpoint"),
    ("auth", 0.25, "Authentication endpoint"),
    ("login", 0.25, "Login endpoint"),
    ("oauth", 0.2, "OAuth endpoint"),
    ("model", 0.2, "AI model endpoint"),
    ("inference", 0.2, "Inference endpoint"),
    ("predict", 0.2, "ML prediction endpoint"),
    ("embeddings", 0.2, "Embedding service"),
]


class HVTScorer:
    """Score scan targets by business criticality and attack surface value.

    Parameters
    ----------
    use_llm:
        If True and AutoGen/OpenAI is available, uses Phase 2 LLM
        contextual reasoning.  Falls back to Phase 1 silently.
    """

    def __init__(self, *, use_llm: bool = False) -> None:
        self._use_llm = use_llm

    def score(self, ctx: ScanContext) -> List[TargetScore]:
        """Return targets sorted by priority (highest first).

        Results are also stored in ``ctx.metadata["hvt_scores"]``.
        """
        scores = [self._score_target(target, ctx) for target in ctx.targets]
        scores.sort(key=lambda s: s.score, reverse=True)

        if self._use_llm:
            scores = self._phase2_llm_rerank(scores, ctx)

        ctx.metadata["hvt_scores"] = scores
        return scores

    # ------------------------------------------------------------------
    # Phase 1 — pattern matching
    # ------------------------------------------------------------------

    def _score_target(self, target: Target, ctx: ScanContext) -> TargetScore:
        score = 0.0
        signals: List[str] = []

        # --- Fingerprint signals ---
        fp_result = ctx.metadata.get("fingerprints", {}).get(target.url)
        techs = set(getattr(fp_result, "technologies", [])) if fp_result else set()

        if techs & _PAYMENT_SIGNALS:
            score += 0.4
            signals.append(f"Payment technology detected: {', '.join(techs & _PAYMENT_SIGNALS)}")

        if techs & _AUTH_SIGNALS:
            score += 0.3
            signals.append(f"Auth technology detected: {', '.join(techs & _AUTH_SIGNALS)}")

        if techs & _AI_SIGNALS:
            score += 0.25
            signals.append(f"AI inference endpoint: {', '.join(techs & _AI_SIGNALS)}")

        if techs & _DATA_SIGNALS:
            score += 0.2
            signals.append(f"Data store detected: {', '.join(techs & _DATA_SIGNALS)}")

        if techs & _ADMIN_SIGNALS:
            score += 0.2
            signals.append(f"Admin surface detected: {', '.join(techs & _ADMIN_SIGNALS)}")

        # --- URL keyword signals ---
        url_lower = target.url.lower()
        for keyword, weight, label in _URL_KEYWORDS:
            if keyword in url_lower:
                score += weight
                signals.append(label)

        # --- Finding severity signals ---
        target_findings = [
            f for f in ctx.findings
            if f.target and f.target.url == target.url
        ]
        critical_count = sum(1 for f in target_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in target_findings if f.severity == Severity.HIGH)
        score += critical_count * 0.15 + high_count * 0.05

        if critical_count:
            signals.append(f"{critical_count} CRITICAL finding(s)")
        if high_count:
            signals.append(f"{high_count} HIGH finding(s)")

        # --- High-impact tag signals ---
        for f in target_findings:
            for tag in f.tags:
                if tag in _HIGH_IMPACT_TAGS:
                    score += 0.1
                    signals.append(f"Finding with tag: {tag}")
                    break  # one bonus per finding

        # --- Attack chain participation ---
        chains = ctx.metadata.get("attack_chains", [])
        chain_count = sum(
            1 for chain in chains
            if any(s.target and s.target.url == target.url for s in chain.steps)
        )
        if chain_count:
            score += chain_count * 0.2
            signals.append(f"Appears in {chain_count} attack chain(s)")

        # --- Cloud inventory signals (S3, high-value resource) ---
        inv = ctx.metadata.get("aws_inventory", {})
        if inv.get("sagemaker_endpoints") or inv.get("bedrock_models"):
            score += 0.2
            signals.append("AWS AI/ML infrastructure in scope")

        # Normalise to [0, 1]
        score = min(score, 1.0)

        priority = (
            "critical" if score >= 0.75 else
            "high" if score >= 0.5 else
            "medium" if score >= 0.25 else
            "low"
        )

        return TargetScore(
            target=target,
            score=score,
            priority=priority,
            signals=signals,
        )

    # ------------------------------------------------------------------
    # Phase 2 — optional LLM reranking (AutoGen)
    # ------------------------------------------------------------------

    def _phase2_llm_rerank(
        self, scores: List[TargetScore], ctx: ScanContext
    ) -> List[TargetScore]:
        """Use AutoGen to contextually rerank high-scoring targets."""
        try:
            from krumpa.core.ai_orchestrator import AttackPlannerAgent
            planner = AttackPlannerAgent()
            return planner.rerank_hvt(scores, ctx)
        except ImportError:
            logger.debug("AutoGen not installed — skipping Phase 2 HVT reranking")
            return scores
        except Exception as exc:
            logger.warning("Phase 2 HVT reranking failed: %s", exc)
            return scores
