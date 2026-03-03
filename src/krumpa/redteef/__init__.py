"""
RedTeef — Exploit Confirmation module.

Responsibilities:
    - Validate suspected vulnerabilities with safe proof-of-concept requests
    - Confirm or dismiss findings from other modules (reduced false positives)
    - Produce evidence payloads and impact assessments
"""

from krumpa.redteef.confirmer import Confirmer, ConfirmationResult
from krumpa.redteef.payload_builder import PayloadBuilder, ProofPayload
from krumpa.redteef.blind_sqli import BlindSqliConfirmer
from krumpa.redteef.env_payloads import EnvironmentPayloadSelector
from krumpa.redteef.oob_verifier import OobVerifier, OobToken, OobCallback, OobVerification
from krumpa.redteef.module import RedTeefModule

__all__ = [
    "RedTeefModule",
    "Confirmer",
    "ConfirmationResult",
    "PayloadBuilder",
    "ProofPayload",
    "BlindSqliConfirmer",
    "EnvironmentPayloadSelector",
    "OobVerifier",
    "OobToken",
    "OobCallback",
    "OobVerification",
]
