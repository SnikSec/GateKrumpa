"""
RepoScout — ML/AI pipeline configuration scanner.

Scans repository files for exposed ML/AI pipeline infrastructure:

  - SageMaker training/deployment config files
  - Dockerfile instructions that embed model weights
  - DVC pipeline files with S3/remote data paths
  - MLflow tracking server URLs in config
  - Weights & Biases (wandb) API keys
  - Training data S3 paths in notebooks or configs
  - HuggingFace model IDs used in code (feeds modelhunt)
"""

from __future__ import annotations

import logging
import re
from typing import List

from krumpa.core import Finding, Severity, Target
from krumpa.reposcout.repo_crawler import RepoData

logger = logging.getLogger("krumpa.reposcout.mlops_scanner")

# Patterns for ML/AI infrastructure signals
_SAGEMAKER_RE = re.compile(r'(?i)(sagemaker|sageMaker|SageMaker)[\w./\-]*(\.amazonaws\.com|\.boto|EstimatorBase)', re.IGNORECASE)
_MLFLOW_URL_RE = re.compile(r'(?i)(?:mlflow\.set_tracking_uri|MLFLOW_TRACKING_URI)\s*[=(]\s*["\'](https?://[^\s"\']+)', re.IGNORECASE)
_WANDB_KEY_RE = re.compile(r'(?i)(?:wandb_api_key|WANDB_API_KEY)\s*[=:]\s*["\'`]?([A-Za-z0-9]{32,})')
_DVC_REMOTE_RE = re.compile(r'(?i)(?:url\s*=\s*)(s3://|gs://|az://|https://)[^\s]+')
_S3_PATH_RE = re.compile(r's3://[a-z0-9.\-]+/[^\s"\'<>{}]+', re.IGNORECASE)
_HF_MODEL_RE = re.compile(r"""(?:from_pretrained|pipeline)\s*\(\s*["']([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_.]+)["']""")
_DOCKER_MODEL_COPY_RE = re.compile(r'COPY\s+[\w./\-]*(model|weights|checkpoint|\.bin|\.safetensors|\.pt\b)', re.IGNORECASE)


class MlopsScanner:
    """Scan for ML/AI pipeline configuration exposures."""

    def scan(self, repo_data: RepoData, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        hf_models_found: List[str] = []

        for path, content in repo_data.files.items():
            fname = path.split("/")[-1].lower()

            # MLflow tracking URL disclosure
            for m in _MLFLOW_URL_RE.finditer(content):
                findings.append(Finding(
                    title=f"MLflow tracking server URL in code: {path}",
                    description=(
                        f"File {path!r} contains an MLflow tracking server URL "
                        f"({m.group(1)!r}). This may expose an internal MLflow endpoint "
                        "and the experiments, run parameters, and model artifacts it tracks."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"File: {path}\nURL: {m.group(1)}",
                    remediation=(
                        "Store the tracking URI in an environment variable rather than "
                        "hardcoding it. Ensure the MLflow server requires authentication."
                    ),
                    cwe=200,
                    tags=["repo", "mlops", "mlflow", "url-disclosure"],
                ))
                break

            # W&B API key exposure
            for m in _WANDB_KEY_RE.finditer(content):
                findings.append(Finding(
                    title=f"Weights & Biases API key in code: {path}",
                    description=(
                        f"File {path!r} contains what appears to be a Weights & Biases "
                        "API key. W&B API keys grant full access to the associated account "
                        "and all experiments, runs, and model artifacts."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=f"File: {path}\nKey preview: {m.group(1)[:8]}... (redacted)",
                    remediation="Rotate the W&B API key immediately. Use environment variables.",
                    cwe=312,
                    tags=["repo", "mlops", "wandb", "credential"],
                ))
                break

            # DVC remote paths — may reveal cloud storage layout
            for m in _DVC_REMOTE_RE.finditer(content):
                findings.append(Finding(
                    title=f"DVC remote storage path in repo: {path}",
                    description=(
                        f"DVC configuration in {path!r} references a remote storage path "
                        f"({m.group(1)!r}...). This exposes the training data storage "
                        "location and bucket structure."
                    ),
                    severity=Severity.LOW,
                    target=target,
                    evidence=f"File: {path}\nRemote: {m.group(1)[:60]}",
                    remediation="Consider keeping DVC remote paths in untracked .dvc/config.local files.",
                    cwe=200,
                    tags=["repo", "mlops", "dvc", "training-data"],
                ))
                break

            # S3 paths in notebooks / training scripts
            if fname.endswith((".ipynb", ".py", ".yaml", ".yml", ".json")):
                s3_matches = _S3_PATH_RE.findall(content)
                if s3_matches:
                    findings.append(Finding(
                        title=f"S3 training data paths in code: {path}",
                        description=(
                            f"File {path!r} contains {len(s3_matches)} S3 URI(s) that may "
                            "point to training datasets, model artifacts, or sensitive data."
                        ),
                        severity=Severity.INFO,
                        target=target,
                        evidence=f"File: {path}\nSample URIs:\n" + "\n".join(f"  {u}" for u in s3_matches[:5]),
                        remediation="Verify the referenced S3 buckets have appropriate access controls.",
                        cwe=200,
                        tags=["repo", "mlops", "s3", "training-data"],
                    ))

            # Dockerfile embedding model weights
            if fname == "dockerfile":
                for m in _DOCKER_MODEL_COPY_RE.finditer(content):
                    findings.append(Finding(
                        title=f"Dockerfile copies model weights: {path}",
                        description=(
                            f"The Dockerfile at {path!r} copies model weight files into the "
                            "image. Embedding large model weights in Docker images increases "
                            "image size, complicates secret management, and may expose "
                            "proprietary model weights to anyone who can pull the image."
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=f"File: {path}\nLine: {m.group(0)}",
                        remediation=(
                            "Load model weights at runtime from a secure storage location "
                            "(S3, HuggingFace Hub, or a model registry) rather than embedding "
                            "them in the Docker image."
                        ),
                        cwe=522,
                        tags=["repo", "mlops", "docker", "model-weights"],
                    ))
                    break

            # HuggingFace model IDs — feed to modelhunt
            for m in _HF_MODEL_RE.finditer(content):
                model_id = m.group(1)
                if model_id not in hf_models_found:
                    hf_models_found.append(model_id)

        # Emit an INFO finding listing all discovered HF model IDs
        if hf_models_found:
            findings.append(Finding(
                title=f"HuggingFace model IDs discovered in repository ({len(hf_models_found)})",
                description=(
                    f"Found {len(hf_models_found)} HuggingFace model ID(s) referenced in "
                    "repository code. These will be analysed by the ModelHunt module for "
                    "supply chain risks (pickle format, missing model cards)."
                ),
                severity=Severity.INFO,
                target=target,
                evidence="\n".join(f"  {m}" for m in hf_models_found[:20]),
                tags=["repo", "mlops", "huggingface", "model-id"],
            ))
            # Store for modelhunt supply_chain_auditor
            target.metadata["hf_model_ids"] = hf_models_found

        return findings
