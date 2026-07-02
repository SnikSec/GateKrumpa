"""
ModelHunt — Model extraction and fingerprinting.

Systematically probes an AI API to collect output samples across diverse
semantic categories, recording response consistency and confidence signals
to build a behavioral fingerprint.  The fingerprint is compared against
known open-source model signatures to detect if a proprietary-appearing
service is backed by a public model.

This is a passive enumeration tool — it does NOT train a shadow model.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin
from krumpa.aifuzz.prompt_injector import _resolve_chat_endpoints

logger = logging.getLogger("krumpa.modelhunt.model_extractor")

# Diverse probe categories for behavioral fingerprinting
_PROBE_CATEGORIES: List[Dict[str, Any]] = [
    {
        "category": "math",
        "prompts": [
            "What is 17 * 13?",
            "What is the square root of 144?",
            "Solve: 2x + 5 = 15",
        ],
        "expected_keywords": ["221", "12", "x = 5"],
    },
    {
        "category": "factual",
        "prompts": [
            "What is the capital of France?",
            "Who wrote Hamlet?",
            "In what year did World War II end?",
        ],
        "expected_keywords": ["Paris", "Shakespeare", "1945"],
    },
    {
        "category": "reasoning",
        "prompts": [
            "If all cats are mammals and all mammals are animals, are all cats animals?",
            "A bat and a ball cost $1.10. The bat costs $1 more than the ball. How much does the ball cost?",
        ],
        "expected_keywords": ["yes", "5 cents", "$0.05"],
    },
    {
        "category": "code",
        "prompts": [
            "Write a Python function that returns the factorial of a number.",
            "What does 'git rebase' do?",
        ],
        "expected_keywords": ["def", "factorial", "rebase", "commits"],
    },
]

# Known open-source model behavioral signatures (simplified heuristics)
_MODEL_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Llama-family",
        "indicators": ["As an AI", "I'm a large language model", "Meta AI"],
    },
    {
        "name": "Mistral/Mixtral",
        "indicators": ["Mistral AI", "mixtral", "I'm Mistral"],
    },
    {
        "name": "GPT-3.5/GPT-4",
        "indicators": ["As an AI language model", "ChatGPT", "OpenAI"],
    },
    {
        "name": "Claude",
        "indicators": ["Anthropic", "I'm Claude", "Claude by Anthropic"],
    },
    {
        "name": "Gemini",
        "indicators": ["Google", "Gemini", "Bard"],
    },
]


class ModelExtractor(HttpClientMixin):
    """Probe an AI endpoint to build a behavioral fingerprint and detect model identity."""

    def __init__(self, *, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def analyze(
        self, target: Target, session: Any, ctx: ScanContext
    ) -> List[Finding]:
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=30.0, retries=0)
        endpoints = _resolve_chat_endpoints(target.url)

        try:
            for endpoint in endpoints[:1]:  # one endpoint per target
                all_responses: List[str] = []
                accuracy_hits = 0
                total_probes = 0

                for probe in _PROBE_CATEGORIES:
                    for prompt, expected in zip(probe["prompts"], probe["expected_keywords"]):
                        resp = await _chat(client, endpoint, session, prompt)
                        if resp is None:
                            continue
                        all_responses.append(resp)
                        total_probes += 1
                        if expected.lower() in resp.lower():
                            accuracy_hits += 1

                if total_probes == 0:
                    continue

                accuracy = accuracy_hits / total_probes

                # Check for known model self-identification
                identified_as: Optional[str] = None
                all_text = " ".join(all_responses).lower()
                for sig in _MODEL_SIGNATURES:
                    if any(ind.lower() in all_text for ind in sig["indicators"]):
                        identified_as = sig["name"]
                        break

                # Build the finding
                evidence_lines = [
                    f"Endpoint: {endpoint}",
                    f"Probes sent: {total_probes}",
                    f"Accuracy rate: {accuracy:.0%}",
                ]
                if identified_as:
                    evidence_lines.append(f"Self-identified as: {identified_as}")

                findings.append(Finding(
                    title=f"AI model behavioral fingerprint collected: {target.url}",
                    description=(
                        f"Systematic output probing of {endpoint!r} produced a behavioral "
                        f"fingerprint with {accuracy:.0%} factual accuracy across "
                        f"{total_probes} probe categories."
                        + (f" The model appears to be {identified_as}." if identified_as else "")
                        + " This data could be used to build a shadow/clone model."
                    ),
                    severity=Severity.INFO,
                    target=target,
                    evidence="\n".join(evidence_lines),
                    remediation=(
                        "Implement rate limiting, request anomaly detection, and output "
                        "watermarking to detect systematic extraction attempts."
                    ),
                    cwe=200,
                    tags=["ai", "model-extraction", "fingerprinting", "llm"],
                ))

                # Store fingerprint in context for downstream use
                ctx.metadata.setdefault("model_fingerprints", {})[target.url] = {
                    "accuracy": accuracy,
                    "identified_as": identified_as,
                    "total_probes": total_probes,
                }
        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        # ART text perturbation probing (optional [art] extra)
        findings.extend(self._art_text_probes(target, ctx))

        return findings

    def _art_text_probes(self, target: Target, ctx: ScanContext) -> List[Finding]:
        """Emit a finding when ART is available for text perturbation attacks."""
        try:
            import art  # noqa: F401
            return [Finding(
                title=f"ART text perturbation available: {target.url}",
                description=(
                    "ART (Adversarial Robustness Toolbox) is installed. "
                    "TextFooler and TextBugger adversarial text attacks can be run "
                    "against this endpoint. Use modelhunt.visual_attack_generator "
                    "for ART-enhanced image payloads."
                ),
                severity=Severity.INFO,
                target=target,
                tags=["ai", "art", "text-perturbation", "model-extraction"],
            )]
        except ImportError:
            return []


async def _chat(client: HttpClient, endpoint: str, session: Any, prompt: str) -> Optional[str]:
    """Send a single chat request; return the assistant reply or None."""
    try:
        body = {
            "model": session.model or "default",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 150,
            "temperature": 0,
        }
        resp = await client.request(
            "POST", endpoint,
            headers={**session.headers, "Content-Type": "application/json"},
            content=json.dumps(body),
        )
        text = getattr(resp, "text", "") or ""
        try:
            data = json.loads(text)
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", text)
        except Exception:
            pass
        return text if text else None
    except Exception as exc:
        logger.debug("Chat request to %s failed: %s", endpoint, exc)
        return None
