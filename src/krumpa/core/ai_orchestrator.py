"""
GateKrumpa core — AutoGen-based AI orchestration layer.

Optional.  Requires ``pip install gatekrumpa[ai]`` (autogen-agentchat, openai).

Provides two agents:

``TryHarderAgent``
    When a module hits a dead-end or a security control blocks further
    progress, this agent reviews the context and suggests alternative
    attack techniques — simulating the persistence of a seasoned red teamer.

``AttackPlannerAgent``
    Reviews the Phase 1A/1B findings summary and proposes a Phase 2 scan
    plan: which modules to run, which targets to prioritise, which attack
    types to focus on.  Also used by :class:`~krumpa.core.hvt_scorer.HVTScorer`
    for Phase 2 LLM-assisted HVT reranking.

Both agents degrade gracefully: if AutoGen or an LLM API key is not
available, they return empty suggestions without raising.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext

logger = logging.getLogger("krumpa.core.ai_orchestrator")

# Environment variable name for the LLM API key (OpenAI-compatible)
_API_KEY_ENV = "GATEKRUMPA_LLM_KEY"
_API_BASE_ENV = "GATEKRUMPA_LLM_BASE"
_MODEL_ENV = "GATEKRUMPA_LLM_MODEL"


def _autogen_available() -> bool:
    """Return True if autogen-agentchat is importable."""
    try:
        import autogen  # noqa: F401
        return True
    except ImportError:
        return False


def _llm_config() -> Optional[Dict[str, Any]]:
    """Build AutoGen LLM config from environment variables."""
    import os
    api_key = os.environ.get(_API_KEY_ENV, "")
    if not api_key:
        return None
    config: Dict[str, Any] = {
        "model": os.environ.get(_MODEL_ENV, "gpt-4o"),
        "api_key": api_key,
    }
    base_url = os.environ.get(_API_BASE_ENV, "")
    if base_url:
        config["base_url"] = base_url
    return {"config_list": [config], "temperature": 0.2}


class TryHarderAgent:
    """AutoGen agent that suggests alternative techniques when a module is blocked.

    Parameters
    ----------
    llm_config:
        AutoGen-compatible LLM config dict.  If omitted the config is
        loaded from environment variables.  If no API key is available
        the agent returns empty suggestions silently.
    """

    def __init__(self, llm_config: Optional[Dict[str, Any]] = None) -> None:
        self._llm_config = llm_config or _llm_config()

    def suggest_alternatives(
        self,
        dead_end_context: str,
        *,
        max_suggestions: int = 5,
    ) -> List[str]:
        """Return alternative attack techniques for the given dead-end context.

        Parameters
        ----------
        dead_end_context:
            Description of what was tried and what blocked progress
            (e.g. "SSRF probe to 169.254.169.254 blocked by WAF response").
        max_suggestions:
            Maximum number of suggestions to return.

        Returns
        -------
        List[str]
            Human-readable suggestion strings, or empty list if AutoGen
            is unavailable or the LLM call fails.
        """
        if not _autogen_available() or not self._llm_config:
            logger.debug("TryHarderAgent: AutoGen/LLM not available — returning empty suggestions")
            return []

        try:
            import autogen
            assistant = autogen.AssistantAgent(
                name="try_harder_assistant",
                llm_config=self._llm_config,
                system_message=(
                    "You are an expert penetration tester. When given a dead-end "
                    "situation during a security assessment, suggest concrete alternative "
                    "techniques. Be specific, practical, and concise. Output a numbered "
                    "list of up to 5 alternative approaches. Do not include disclaimers."
                ),
            )

            proxy = autogen.UserProxyAgent(
                name="orchestrator",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )

            proxy.initiate_chat(
                assistant,
                message=(
                    f"Dead-end context: {dead_end_context}\n\n"
                    f"Suggest up to {max_suggestions} alternative techniques."
                ),
            )

            # Extract the assistant's last message
            messages = assistant.chat_messages.get(proxy, [])
            if messages:
                last = messages[-1].get("content", "")
                # Parse numbered list
                lines = [
                    line.lstrip("0123456789. ").strip()
                    for line in last.splitlines()
                    if line.strip() and any(c.isdigit() for c in line[:3])
                ]
                return lines[:max_suggestions]

        except Exception as exc:
            logger.debug("TryHarderAgent suggestion failed: %s", exc)

        return []


class AttackPlannerAgent:
    """AutoGen agent that plans the next phase of a scan based on findings.

    Also used by :class:`~krumpa.core.hvt_scorer.HVTScorer` for Phase 2
    HVT contextual reranking.
    """

    def __init__(self, llm_config: Optional[Dict[str, Any]] = None) -> None:
        self._llm_config = llm_config or _llm_config()

    def plan_next_phase(self, ctx: ScanContext) -> Dict[str, Any]:
        """Return a structured scan plan based on current findings.

        Returns an empty dict if AutoGen/LLM is not available.
        """
        if not _autogen_available() or not self._llm_config:
            return {}

        try:
            import autogen

            summary = ctx.summary()
            top_findings = sorted(
                ctx.findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity.value, 0),
                reverse=True,
            )[:10]

            finding_text = "\n".join(
                f"- [{f.severity.value.upper()}] {f.title}" for f in top_findings
            )

            assistant = autogen.AssistantAgent(
                name="attack_planner",
                llm_config=self._llm_config,
                system_message=(
                    "You are an expert penetration testing strategist. Based on a summary "
                    "of current scan findings, recommend which additional modules to run "
                    "and which targets to prioritise. Be specific and output valid JSON."
                ),
            )
            proxy = autogen.UserProxyAgent(
                name="orchestrator",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )

            prompt = (
                f"Scan summary: {json.dumps(summary)}\n\n"
                f"Top findings:\n{finding_text}\n\n"
                "Output JSON with keys: 'priority_modules' (list), "
                "'priority_targets' (list of URLs), 'rationale' (string)."
            )

            proxy.initiate_chat(assistant, message=prompt)

            messages = assistant.chat_messages.get(proxy, [])
            if messages:
                content = messages[-1].get("content", "")
                # Extract JSON block
                start = content.find("{")
                end = content.rfind("}") + 1
                if start >= 0 and end > start:
                    return json.loads(content[start:end])

        except Exception as exc:
            logger.debug("AttackPlannerAgent.plan_next_phase failed: %s", exc)

        return {}

    def rerank_hvt(
        self,
        scores: List[Any],
        ctx: ScanContext,
    ) -> List[Any]:
        """Contextually rerank HVT scores using LLM reasoning.

        If the LLM is unavailable, returns the original scores unchanged.
        """
        if not _autogen_available() or not self._llm_config:
            return scores

        try:
            import autogen

            score_text = "\n".join(
                f"- {s.target.url}: score={s.score:.2f}, signals={', '.join(s.signals[:3])}"
                for s in scores[:20]
            )

            assistant = autogen.AssistantAgent(
                name="hvt_reranker",
                llm_config=self._llm_config,
                system_message=(
                    "You are a security strategist. Reorder these targets by actual "
                    "business risk using context clues. Output a JSON array of URLs "
                    "in priority order (most critical first)."
                ),
            )
            proxy = autogen.UserProxyAgent(
                name="orchestrator",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )

            proxy.initiate_chat(
                assistant,
                message=f"Reorder these targets by business risk:\n{score_text}\n\nOutput JSON array of URLs.",
            )

            messages = assistant.chat_messages.get(proxy, [])
            if messages:
                content = messages[-1].get("content", "")
                start = content.find("[")
                end = content.rfind("]") + 1
                if start >= 0 and end > start:
                    priority_urls = json.loads(content[start:end])
                    # Reorder scores list according to LLM priority
                    url_to_score = {s.target.url: s for s in scores}
                    reordered = [url_to_score[u] for u in priority_urls if u in url_to_score]
                    # Append any scores not mentioned by LLM at the end
                    mentioned = set(priority_urls)
                    reordered.extend(s for s in scores if s.target.url not in mentioned)
                    return reordered

        except Exception as exc:
            logger.debug("AttackPlannerAgent.rerank_hvt failed: %s", exc)

        return scores
