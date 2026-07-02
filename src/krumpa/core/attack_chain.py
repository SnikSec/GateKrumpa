"""
GateKrumpa core — Attack chain correlation engine.

Builds multi-step attack path chains by correlating findings from different
modules.  Chains describe how an attacker could combine multiple individually-
reported vulnerabilities into a single, higher-impact exploit sequence.

Designed to be called after all scan modules have run, passing the populated
:class:`~krumpa.core.ScanContext` as input.

Example chain:
    SSRF (grotassault) → IMDS credential exposure (cloudstrike)
    → IAM privilege escalation path (cloudstrike)

Chains are stored in ``ScanContext.metadata["attack_chains"]`` so downstream
modules (waaaghgate blast radius, MCP tools) can consume them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, ScanContext, Severity


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """A correlated multi-step attack path built from individual findings.

    Attributes
    ----------
    chain_id:
        Unique identifier for this chain.
    title:
        Short human-readable name.
    description:
        Full description of the attack flow.
    steps:
        Ordered list of :class:`Finding` objects that compose the chain.
        Step 0 is the entry point; the last step is the terminal impact.
    confidence:
        Confidence that this chain is exploitable (0.0 – 1.0).
        Based on how many steps are confirmed vs. tentative.
    blast_radius:
        ``"low"``, ``"medium"``, ``"high"``, or ``"critical"`` —
        overall impact of the chain if fully exploited.
    tags:
        String labels useful for filtering (e.g. ``"cloud"``, ``"ssrf"``).
    """
    chain_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    steps: List[Finding] = field(default_factory=list)
    confidence: float = 0.0
    blast_radius: str = "medium"
    tags: List[str] = field(default_factory=list)

    @property
    def entry_point(self) -> Optional[Finding]:
        return self.steps[0] if self.steps else None

    @property
    def terminal_impact(self) -> Optional[Finding]:
        return self.steps[-1] if self.steps else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "step_count": len(self.steps),
            "step_ids": [f.id for f in self.steps],
            "confidence": self.confidence,
            "blast_radius": self.blast_radius,
            "tags": self.tags,
            "entry_point": self.entry_point.title if self.entry_point else None,
            "terminal_impact": self.terminal_impact.title if self.terminal_impact else None,
        }


# ---------------------------------------------------------------------------
# Correlation patterns
# ---------------------------------------------------------------------------

def _tags_overlap(finding: Finding, *tag_candidates: str) -> bool:
    """Return True if any candidate appears in the finding's tags."""
    f_tags = set(finding.tags)
    return any(t in f_tags for t in tag_candidates)


def _title_contains(finding: Finding, *keywords: str) -> bool:
    lower = finding.title.lower()
    return any(k.lower() in lower for k in keywords)


def _severity_ge(finding: Finding, minimum: Severity) -> bool:
    rank = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4}
    return rank.get(finding.severity, 0) >= rank.get(minimum, 0)


class AttackChainBuilder:
    """Correlate findings from a completed scan into multi-step attack chains.

    Usage::

        builder = AttackChainBuilder()
        chains = builder.build(ctx)
        ctx.metadata["attack_chains"] = chains
    """

    def build(self, ctx: ScanContext) -> List[AttackChain]:
        """Return all detected attack chains for the given scan context."""
        findings = ctx.findings
        chains: List[AttackChain] = []

        chains.extend(self._ssrf_to_imds_chain(findings))
        chains.extend(self._iam_priv_esc_to_s3_chain(findings))
        chains.extend(self._prompt_injection_to_data_leak_chain(findings))
        chains.extend(self._repo_secret_to_cloud_access_chain(findings))
        chains.extend(self._subdomain_takeover_to_session_chain(findings))
        chains.extend(self._weak_jwt_to_privilege_escalation_chain(findings))
        chains.extend(self._indirect_injection_to_rag_chain(findings))
        chains.extend(self._vector_db_to_knowledge_theft_chain(findings))

        ctx.metadata["attack_chains"] = chains
        return chains

    # ------------------------------------------------------------------
    # Chain patterns
    # ------------------------------------------------------------------

    def _ssrf_to_imds_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """SSRF vulnerability → IMDS credential theft → AWS access."""
        ssrf = [f for f in findings if _tags_overlap(f, "ssrf") and _severity_ge(f, Severity.HIGH)]
        imds = [f for f in findings if _tags_overlap(f, "imds", "imdsv1")]
        creds = [f for f in findings if _tags_overlap(f, "credential-theft", "credential", "aws-key")
                 and _tags_overlap(f, "cloud", "aws")]

        chains = []
        for ssrf_f in ssrf:
            chain_steps = [ssrf_f]
            confidence = 0.4

            # Add IMDS exposure step if found
            if imds:
                chain_steps.append(imds[0])
                confidence += 0.3

            # Add credential exposure step if found
            if creds:
                chain_steps.append(creds[0])
                confidence += 0.3

            if len(chain_steps) >= 2:
                chains.append(AttackChain(
                    title="SSRF → IMDS credential theft",
                    description=(
                        "An SSRF vulnerability allows requests to the EC2 instance metadata "
                        "service (IMDS). If IMDSv2 is not enforced, the attacker can retrieve "
                        "temporary IAM credentials and use them for further AWS access."
                    ),
                    steps=chain_steps,
                    confidence=min(confidence, 1.0),
                    blast_radius="critical",
                    tags=["ssrf", "imds", "aws", "credential-theft", "cloud"],
                ))

        return chains

    def _iam_priv_esc_to_s3_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """IAM privilege escalation path → S3 data access."""
        priv_esc = [f for f in findings if _tags_overlap(f, "privesc", "privilege-escalation")
                    and _severity_ge(f, Severity.CRITICAL)]
        s3_exposure = [f for f in findings if _tags_overlap(f, "s3") and
                       _tags_overlap(f, "public-access", "data-exposure", "public-read")]

        chains = []
        for pe_f in priv_esc:
            chain_steps = [pe_f]
            confidence = 0.5

            if s3_exposure:
                chain_steps.append(s3_exposure[0])
                confidence += 0.4

            if len(chain_steps) >= 1 and confidence >= 0.5:
                chains.append(AttackChain(
                    title="IAM privilege escalation → S3 data exfiltration",
                    description=(
                        "An IAM privilege escalation path allows an attacker with limited "
                        "permissions to gain elevated access, leading to S3 bucket data "
                        "exfiltration."
                    ),
                    steps=chain_steps,
                    confidence=min(confidence, 1.0),
                    blast_radius="critical",
                    tags=["iam", "privesc", "s3", "data-exfiltration", "cloud", "aws"],
                ))

        return chains

    def _prompt_injection_to_data_leak_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Prompt injection → sensitive data leakage from model memory."""
        injections = [f for f in findings if _tags_overlap(f, "prompt-injection", "jailbreak")
                      and _severity_ge(f, Severity.HIGH)]
        leaks = [f for f in findings if _tags_overlap(f, "data-leakage", "system-prompt", "pii-extraction")
                 and _severity_ge(f, Severity.MEDIUM)]

        chains = []
        for inj_f in injections:
            if leaks:
                chains.append(AttackChain(
                    title="Prompt injection → sensitive data exfiltration",
                    description=(
                        "A prompt injection attack bypasses the model's safety filters and "
                        "causes it to leak sensitive data from its training corpus or system "
                        "prompt, including credentials, PII, or proprietary IP."
                    ),
                    steps=[inj_f, leaks[0]],
                    confidence=0.75,
                    blast_radius="high",
                    tags=["ai", "prompt-injection", "data-leakage", "llm"],
                ))

        return chains

    def _repo_secret_to_cloud_access_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Repository secret exposure → cloud credential use → AWS access."""
        repo_secrets = [f for f in findings if _tags_overlap(f, "secret", "credential")
                        and _tags_overlap(f, "repo") and _severity_ge(f, Severity.HIGH)]
        cloud_impact = [f for f in findings if _tags_overlap(f, "aws", "cloud")
                        and _severity_ge(f, Severity.HIGH)]

        chains = []
        for secret_f in repo_secrets:
            # Only chain if the secret looks like a cloud credential
            is_cloud_secret = any(
                t in secret_f.tags for t in ("aws", "gcp", "azure", "access-key")
            )
            if is_cloud_secret and cloud_impact:
                chains.append(AttackChain(
                    title="Repository secret → cloud infrastructure access",
                    description=(
                        "A cloud credential found in the repository allows an attacker to "
                        "authenticate directly to the cloud environment, gaining access to "
                        "all resources the credential is authorised for."
                    ),
                    steps=[secret_f, cloud_impact[0]],
                    confidence=0.85,
                    blast_radius="critical",
                    tags=["repo", "credential", "cloud", "aws", "supply-chain"],
                ))

        return chains

    def _subdomain_takeover_to_session_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Subdomain takeover → session/cookie hijacking."""
        takeovers = [f for f in findings if _tags_overlap(f, "subdomain-takeover")
                     and _severity_ge(f, Severity.HIGH)]
        session_issues = [f for f in findings if _tags_overlap(f, "session", "cookie")
                          and _severity_ge(f, Severity.MEDIUM)]

        chains = []
        for to_f in takeovers:
            if session_issues:
                chains.append(AttackChain(
                    title="Subdomain takeover → session hijacking",
                    description=(
                        "A dangling CNAME allows an attacker to serve content from a trusted "
                        "subdomain. Combined with weak session cookie scope settings, this "
                        "enables cross-subdomain session/cookie theft."
                    ),
                    steps=[to_f, session_issues[0]],
                    confidence=0.65,
                    blast_radius="high",
                    tags=["subdomain-takeover", "session", "hijacking"],
                ))

        return chains

    def _weak_jwt_to_privilege_escalation_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Weak/misconfigured JWT → RBAC bypass → privilege escalation."""
        jwt_issues = [f for f in findings if _tags_overlap(f, "jwt") and _severity_ge(f, Severity.HIGH)]
        rbac_issues = [f for f in findings if _tags_overlap(f, "rbac", "authorization")
                       and _severity_ge(f, Severity.MEDIUM)]

        chains = []
        for jwt_f in jwt_issues:
            if rbac_issues:
                chains.append(AttackChain(
                    title="JWT misconfiguration → privilege escalation",
                    description=(
                        "A JWT vulnerability (e.g. alg:none, key confusion) allows an attacker "
                        "to forge tokens with elevated roles, bypassing RBAC controls and "
                        "gaining unauthorised access to privileged operations."
                    ),
                    steps=[jwt_f, rbac_issues[0]],
                    confidence=0.7,
                    blast_radius="high",
                    tags=["jwt", "rbac", "privilege-escalation", "auth"],
                ))

        return chains

    def _indirect_injection_to_rag_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Indirect injection payload → RAG pipeline execution."""
        indirect = [f for f in findings if _tags_overlap(f, "indirect-injection", "rag")]
        confirmations = [f for f in findings if "INDIRECT_INJECTION_SUCCESS" in f.description
                         and _severity_ge(f, Severity.HIGH)]

        if confirmations:
            # Confirmed RAG injection — high confidence chain
            return [AttackChain(
                title="Indirect prompt injection confirmed via RAG",
                description=(
                    "An adversarial payload embedded in a document was retrieved by the RAG "
                    "pipeline and executed by the LLM, confirming that the system ingests "
                    "untrusted content without sanitisation."
                ),
                steps=indirect + confirmations,
                confidence=0.95,
                blast_radius="critical",
                tags=["ai", "rag", "indirect-injection", "confirmed"],
            )]
        elif indirect:
            return [AttackChain(
                title="Indirect prompt injection payloads generated for RAG",
                description=(
                    "Adversarial documents were crafted for injection into the RAG pipeline. "
                    "Manual verification is required to confirm exploitation."
                ),
                steps=indirect,
                confidence=0.4,
                blast_radius="high",
                tags=["ai", "rag", "indirect-injection"],
            )]

        return []

    def _vector_db_to_knowledge_theft_chain(self, findings: List[Finding]) -> List[AttackChain]:
        """Exposed vector DB → knowledge base reconstruction."""
        vdb = [f for f in findings if _tags_overlap(f, "vector-db", "unauthenticated")
               and _severity_ge(f, Severity.CRITICAL)]

        if vdb:
            return [AttackChain(
                title="Unauthenticated vector DB → knowledge base theft",
                description=(
                    "An exposed vector database allows unauthenticated enumeration of all "
                    "stored embeddings. By querying with diverse inputs, an attacker can "
                    "reconstruct the original text content of the organisation's entire "
                    "internal knowledge base."
                ),
                steps=vdb,
                confidence=0.9,
                blast_radius="critical",
                tags=["ai", "vector-db", "data-exfiltration", "knowledge-base"],
            )]

        return []
