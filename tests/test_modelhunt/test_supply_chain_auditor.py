"""Tests for SupplyChainAuditor — dependency and HuggingFace supply chain checks."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.modelhunt.supply_chain_auditor import (
    SupplyChainAuditor,
    _KNOWN_MALICIOUS_PACKAGES,
    _AI_PACKAGE_TYPOSQUATS,
)


class _FakeHFResponse:
    def __init__(self, data: dict):
        self._data = data
        self.status_code = 200

    @property
    def text(self) -> str:
        return json.dumps(self._data)


class _FakeHttpClient:
    def __init__(self, response_data: dict):
        self._data = response_data

    async def get(self, url: str, **kw) -> _FakeHFResponse:
        return _FakeHFResponse(self._data)

    async def close(self) -> None:
        pass


@pytest.mark.asyncio
class TestSupplyChainAuditor:

    def _target(self) -> Target:
        return Target(url="https://ai.example.com")

    async def test_flags_pickle_only_model(self):
        hf_data = {
            "siblings": [
                {"rfilename": "pytorch_model.bin"},
                {"rfilename": "tokenizer.json"},
                {"rfilename": "config.json"},
            ],
            "private": False,
            "gated": False,
            "cardData": {"license": "mit"},
            "modelId": "org/model",
        }
        client = _FakeHttpClient(hf_data)
        target = Target(
            url="https://ai.example.com",
            metadata={"hf_model_id": "org/my-model"},
        )
        ctx = ScanContext()

        auditor = SupplyChainAuditor(http_client=client)
        findings = await auditor.audit(target, ctx)

        pickle_findings = [f for f in findings if "pickle" in " ".join(f.tags)]
        assert len(pickle_findings) >= 1
        assert pickle_findings[0].severity == Severity.HIGH

    async def test_no_pickle_finding_when_safetensors_present(self):
        hf_data = {
            "siblings": [
                {"rfilename": "model.safetensors"},
                {"rfilename": "config.json"},
            ],
            "private": False,
            "gated": False,
            "cardData": {"license": "mit"},
            "modelId": "org/safe-model",
        }
        client = _FakeHttpClient(hf_data)
        target = Target(
            url="https://ai.example.com",
            metadata={"hf_model_id": "org/safe-model"},
        )
        ctx = ScanContext()

        auditor = SupplyChainAuditor(http_client=client)
        findings = await auditor.audit(target, ctx)

        pickle_findings = [f for f in findings if "pickle" in " ".join(f.tags)]
        assert pickle_findings == []

    async def test_flags_known_malicious_package_in_requirements(self):
        target = self._target()
        requirements = "numpy\njeilyfish\ntorch"

        auditor = SupplyChainAuditor()
        findings = auditor._audit_requirements_txt(requirements, target)

        assert any("malicious" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_flags_typosquatted_ai_package(self):
        target = self._target()
        requirements = "numpy\ntransformer\ntorch"  # 'transformer' not 'transformers'

        auditor = SupplyChainAuditor()
        findings = auditor._audit_requirements_txt(requirements, target)

        typo_findings = [f for f in findings if "typosquat" in f.title.lower()]
        assert len(typo_findings) >= 1
        assert typo_findings[0].severity == Severity.HIGH

    async def test_clean_requirements_no_findings(self):
        target = self._target()
        requirements = "numpy==1.26.0\ntorch==2.3.0\ntransformers==4.40.0"

        auditor = SupplyChainAuditor()
        findings = auditor._audit_requirements_txt(requirements, target)

        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical_high == []


class TestSupplyChainAuditorHelpers:
    """Sync helper tests."""

    def test_known_malicious_packages_set_is_populated(self):
        assert len(_KNOWN_MALICIOUS_PACKAGES) > 0

    def test_typosquat_map_covers_key_ai_packages(self):
        assert "transformers" in _AI_PACKAGE_TYPOSQUATS
        assert "openai" in _AI_PACKAGE_TYPOSQUATS
        assert "langchain" in _AI_PACKAGE_TYPOSQUATS
