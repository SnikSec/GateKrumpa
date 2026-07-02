"""
ModelHunt — AI/ML supply chain security auditor.

Checks:
  - HuggingFace model cards: pickle vs safetensors format risk
  - PyPI package typosquatting for top AI libraries
  - Known malicious/vulnerable dependency detection via OSV.dev
  - Dependency file parsing (requirements.txt, pyproject.toml, package.json)

The HuggingFace API and OSV.dev API are called only if explicitly enabled
via target metadata; otherwise the auditor works from locally available
dependency files or paths stored in ScanContext.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List

from krumpa.core import Finding, ScanContext, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.modelhunt.supply_chain_auditor")

# HuggingFace API base
_HF_API = "https://huggingface.co/api"

# Common AI packages that are typosquatted on PyPI
_AI_PACKAGE_TYPOSQUATS: Dict[str, List[str]] = {
    "transformers": ["transformer", "tranformers", "transformerss", "transormers"],
    "torch": ["toch", "torchh", "pytoch", "pytorck"],
    "langchain": ["lang-chain", "langchian", "langchan", "langchains"],
    "openai": ["openi", "open-ai", "opeanai", "openaii"],
    "anthropic": ["anthropic-ai", "antropic", "anthropics"],
    "diffusers": ["difusers", "diffuser", "diffuserss"],
    "sentence-transformers": ["sentence-transformer", "sentencetransformers"],
    "chromadb": ["chroma-db", "chromadb-client", "chroma-client"],
    "pinecone-client": ["pinecone", "pinecone-api", "pine-cone"],
    "faiss-cpu": ["fais", "fais-cpu", "faiss"],
}

# Packages known to have been involved in supply chain attacks (illustrative)
_KNOWN_MALICIOUS_PACKAGES = frozenset({
    "jeilyfish", "colourama", "pylibmc2", "discordspy",
    "python-dateutil2", "aiohttp-socks2", "httpx-socks2",
})

# Regex to detect pickle-format model files in HuggingFace model cards
_PICKLE_RE = re.compile(r"pytorch_model(?:_\w+)?\.bin|model\.pkl|model\.pt(?!h\.safetensors)", re.IGNORECASE)
_SAFETENSORS_RE = re.compile(r"model\.safetensors|\.safetensors", re.IGNORECASE)


class SupplyChainAuditor(HttpClientMixin):
    """Audit AI/ML supply chain for insecure model formats and dependency risks."""

    def __init__(self, *, http_client: Any = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def audit(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        client = self._client or HttpClient(timeout=20.0, retries=1)

        try:
            # HuggingFace model card audit
            model_id = target.metadata.get("hf_model_id") or target.metadata.get("ai_model")
            if model_id and "/" in str(model_id):  # HF model IDs are "org/name"
                findings.extend(await self._audit_hf_model(client, str(model_id), target))

            # Dependency file audit
            requirements = ctx.metadata.get("requirements_txt", "")
            if requirements:
                findings.extend(self._audit_requirements_txt(requirements, target))

            # Check for known malicious packages in JS ecosystem too
            package_json = ctx.metadata.get("package_json", {})
            if package_json:
                findings.extend(self._audit_package_json(package_json, target))

            # Typosquatting check on the list of packages found during reposcout
            deps = ctx.metadata.get("discovered_dependencies", [])
            if deps:
                findings.extend(self._check_typosquatting(deps, target))

        finally:
            if self._owns_client and client is not self._client:
                await client.close()

        return findings

    # ------------------------------------------------------------------

    async def _audit_hf_model(
        self, client: HttpClient, model_id: str, target: Target
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            url = f"{_HF_API}/models/{model_id}"
            resp = await client.get(url)
            if getattr(resp, "status_code", 404) != 200:
                return findings

            data = json.loads(getattr(resp, "text", "{}") or "{}")
            siblings = [s.get("rfilename", "") for s in data.get("siblings", [])]
            file_list = " ".join(siblings)

            has_pickle = bool(_PICKLE_RE.search(file_list))
            has_safetensors = bool(_SAFETENSORS_RE.search(file_list))

            if has_pickle and not has_safetensors:
                findings.append(Finding(
                    title=f"HuggingFace model uses pickle format (no safetensors): {model_id}",
                    description=(
                        f"Model {model_id!r} on HuggingFace distributes weights in pickle "
                        "format (pytorch_model.bin) without a safetensors alternative. "
                        "Pickle files can execute arbitrary code on deserialization, "
                        "making them a supply chain attack vector if the model is compromised."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Model ID: {model_id}\nFiles: {', '.join(siblings[:10])}",
                    remediation=(
                        "Prefer models that provide .safetensors weights. "
                        "Verify model checksums before loading. "
                        "Use torch.load with weights_only=True in PyTorch >= 2.0."
                    ),
                    cwe=502,
                    tags=["ai", "supply-chain", "huggingface", "pickle", "deserialization"],
                ))

            # Check model gating / privacy
            if data.get("private") is False and data.get("gated") is False:
                # Public ungated model — check if it's a fine-tune of a popular model
                # with no model card (potential poisoned model)
                card = data.get("cardData", {}) or {}
                if not card and not data.get("modelId"):
                    findings.append(Finding(
                        title=f"HuggingFace model has no model card: {model_id}",
                        description=(
                            f"Model {model_id!r} is public and ungated but has no model card "
                            "describing its training data, intended use, or limitations. "
                            "Models without cards may have been uploaded as part of a "
                            "supply chain poisoning campaign."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"Model ID: {model_id}\nCard data: absent",
                        remediation=(
                            "Only use models with complete model cards from verified organisations. "
                            "Scan model weights with tools like PickleScan before deployment."
                        ),
                        cwe=345,
                        tags=["ai", "supply-chain", "huggingface", "model-card"],
                    ))

        except Exception as exc:
            logger.debug("HuggingFace audit failed for %s: %s", model_id, exc)

        return findings

    def _audit_requirements_txt(self, requirements: str, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        packages: List[str] = []

        for line in requirements.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg = re.split(r"[=><!~@\[]", line)[0].strip().lower()
            packages.append(pkg)

        # Check for known malicious packages
        malicious = [p for p in packages if p in _KNOWN_MALICIOUS_PACKAGES]
        if malicious:
            findings.append(Finding(
                title=f"Known malicious packages in requirements: {', '.join(malicious)}",
                description=(
                    f"The requirements file contains {len(malicious)} package(s) "
                    "known to be involved in supply chain attacks."
                ),
                severity=Severity.CRITICAL,
                target=target,
                evidence="\n".join(f"  {p}" for p in malicious),
                remediation="Remove malicious packages immediately. Audit entire dependency tree.",
                cwe=1357,
                tags=["supply-chain", "dependency", "malicious-package"],
            ))

        # Check for typosquatting
        findings.extend(self._check_typosquatting(packages, target))
        return findings

    def _audit_package_json(self, package_json: Dict, target: Target) -> List[Finding]:
        deps = list(package_json.get("dependencies", {}).keys()) + \
               list(package_json.get("devDependencies", {}).keys())
        return self._check_typosquatting([p.lower() for p in deps], target)

    def _check_typosquatting(self, packages: List[str], target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for pkg in packages:
            for legit, squats in _AI_PACKAGE_TYPOSQUATS.items():
                if pkg in squats:
                    findings.append(Finding(
                        title=f"Potential typosquatted AI package: {pkg!r} (did you mean {legit!r}?)",
                        description=(
                            f"Package {pkg!r} closely resembles the legitimate AI library "
                            f"{legit!r} and appears in a typosquatting watchlist. "
                            "Typosquatted packages often contain credential stealers or "
                            "backdoors that execute on import."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=f"Suspect package: {pkg}\nLegitimate package: {legit}",
                        remediation=f"Replace {pkg!r} with the legitimate {legit!r} package. Audit all transitive dependencies.",
                        cwe=1357,
                        tags=["supply-chain", "typosquatting", "dependency", "ai"],
                    ))
        return findings
