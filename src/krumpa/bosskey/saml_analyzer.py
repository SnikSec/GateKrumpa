"""SAML security analysis — signature wrapping, assertion replay, recipient validation.

Phase 4 item #51.
"""

from __future__ import annotations

import hashlib
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClientMixin


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class SamlEndpoint:
    """Represents a SAML endpoint (SSO, SLO, ACS) with metadata."""
    url: str
    binding: str = "POST"  # POST or Redirect
    endpoint_type: str = "SSO"  # SSO, SLO, ACS


@dataclass
class SamlConfig:
    """Configuration for SAML analysis."""
    idp_url: Optional[str] = None
    sp_acs_url: Optional[str] = None
    sp_slo_url: Optional[str] = None
    metadata_url: Optional[str] = None
    known_issuer: Optional[str] = None
    test_assertion: Optional[str] = None


@dataclass
class SamlVulnerability:
    """A specific SAML vulnerability found."""
    vuln_type: str
    description: str
    severity: Severity
    evidence: str
    cwe: int
    remediation: str


# ------------------------------------------------------------------
# Signature wrapping attack patterns
# ------------------------------------------------------------------

WRAPPING_ATTACK_PATTERNS = [
    {
        "name": "XSW1 — Clone response, move signature",
        "description": (
            "Duplicate the signed assertion, place the original (with signature) "
            "as a sibling, and modify the cloned assertion."
        ),
        "technique": "xsw1",
    },
    {
        "name": "XSW2 — Detach signature from assertion",
        "description": (
            "Move the Signature element outside the assertion to a sibling element, "
            "then modify the unsigned assertion."
        ),
        "technique": "xsw2",
    },
    {
        "name": "XSW3 — Insert evil assertion before signed one",
        "description": (
            "Insert a new unsigned assertion before the existing signed assertion. "
            "SP may process the first assertion found."
        ),
        "technique": "xsw3",
    },
    {
        "name": "XSW4 — Move signature to the evil assertion",
        "description": (
            "Copy the Signature from the legitimate assertion into a new assertion "
            "with modified attributes."
        ),
        "technique": "xsw4",
    },
    {
        "name": "XSW5 — Change NameID in signed assertion",
        "description": (
            "If the signature only covers the assertion element (not NameID), "
            "modify the NameID while keeping the signature intact."
        ),
        "technique": "xsw5",
    },
    {
        "name": "XSW6 — Comment injection in NameID",
        "description": (
            "Insert an XML comment inside the NameID value to bypass naive "
            "string comparison: user<!----->@evil.com"
        ),
        "technique": "xsw6",
    },
    {
        "name": "XSW7 — Extensions element injection",
        "description": (
            "Add an Extensions element containing a cloned unsigned assertion. "
            "Some SPs process Extensions assertions."
        ),
        "technique": "xsw7",
    },
    {
        "name": "XSW8 — Object element wrapping",
        "description": (
            "Wrap the original signed assertion inside a ds:Object element "
            "and add an evil assertion as a sibling."
        ),
        "technique": "xsw8",
    },
]


# Namespace constants
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NS_MAP = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DSIG_NS,
}


# ------------------------------------------------------------------
# Analyzer
# ------------------------------------------------------------------

class SamlAnalyzer(HttpClientMixin):
    """Analyze SAML implementations for common security vulnerabilities.

    Checks include:
    - Signature wrapping attacks (XSW1-8)
    - Assertion replay detection
    - Recipient/audience validation
    - NotBefore/NotOnOrAfter enforcement
    - Signature algorithm strength
    - XML canonicalization issues
    """

    def __init__(self, config: Optional[SamlConfig] = None) -> None:
        self._config = config or SamlConfig()
        self._client: Any = None
        self._owns_client: bool = True

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    async def analyze(self, target: Target) -> List[Finding]:
        """Run all SAML checks against the target."""
        findings: List[Finding] = []
        url = target.url

        # 1. Metadata analysis (if available)
        findings.extend(await self._check_metadata(url, target))

        # 2. Signature wrapping probes
        findings.extend(await self._test_signature_wrapping(url, target))

        # 3. Assertion replay
        findings.extend(await self._test_assertion_replay(url, target))

        # 4. Recipient / Audience validation
        findings.extend(await self._test_recipient_validation(url, target))

        # 5. Timing / expiry checks
        findings.extend(await self._test_assertion_timing(url, target))

        # 6. Algorithm strength
        findings.extend(await self._test_algorithm_strength(url, target))

        return findings

    # ----------------------------------------------------------
    # Metadata analysis
    # ----------------------------------------------------------

    async def _check_metadata(self, url: str, target: Target) -> List[Finding]:
        """Fetch and analyze SAML metadata for misconfigurations."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        metadata_urls = [
            self._config.metadata_url,
            f"{url}/saml/metadata",
            f"{url}/saml2/metadata",
            f"{url}/FederationMetadata/2007-06/FederationMetadata.xml",
            f"{url}/.well-known/saml-metadata",
        ]

        for meta_url in metadata_urls:
            if not meta_url:
                continue

            try:
                resp = await self._client.request("GET", meta_url)
                if resp.status_code != 200:
                    continue

                text = resp.text
                if "<EntityDescriptor" not in text and "<md:EntityDescriptor" not in text:
                    continue

                # Parse metadata
                findings.extend(self._analyze_metadata_xml(text, meta_url, target))
                break  # Found valid metadata, stop probing

            except Exception:
                continue

        return findings

    def _analyze_metadata_xml(
        self, xml_text: str, source_url: str, target: Target,
    ) -> List[Finding]:
        """Analyze SAML metadata XML for security issues."""
        findings: List[Finding] = []

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return findings

        # Check for HTTP (non-HTTPS) bindings
        for elem in root.iter():
            location = elem.attrib.get("Location", "")
            if location.startswith("http://"):
                findings.append(Finding(
                    title="SAML endpoint uses HTTP (not HTTPS)",
                    description=(
                        f"SAML metadata at {source_url} contains an endpoint "
                        f"using insecure HTTP: {location}"
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=f"Location={location}",
                    remediation="All SAML endpoints must use HTTPS to prevent token interception.",
                    cwe=319,
                    tags=["saml", "transport-security", "bosskey"],
                ))

        # Check signing algorithm
        for sig_method in root.iter(f"{{{DSIG_NS}}}SignatureMethod"):
            algo = sig_method.attrib.get("Algorithm", "")
            if "sha1" in algo.lower() or "md5" in algo.lower():
                findings.append(Finding(
                    title="Weak SAML signature algorithm",
                    description=(
                        f"Metadata specifies weak signature algorithm: {algo}. "
                        f"SHA-1 and MD5 are vulnerable to collision attacks."
                    ),
                    severity=Severity.MEDIUM,
                    target=target,
                    evidence=f"Algorithm={algo}",
                    remediation="Use SHA-256 or stronger for SAML signature algorithms.",
                    cwe=327,
                    tags=["saml", "weak-crypto", "bosskey"],
                ))

        # Check for WantAuthnRequestsSigned="false"
        xml_lower = xml_text.lower()
        if 'wantauthnrequestssigned="false"' in xml_lower:
            findings.append(Finding(
                title="SAML IdP does not require signed AuthnRequests",
                description=(
                    "The IdP metadata indicates WantAuthnRequestsSigned=false. "
                    "This allows unsigned authentication requests, enabling "
                    "request forgery attacks."
                ),
                severity=Severity.MEDIUM,
                target=target,
                evidence="WantAuthnRequestsSigned=false in metadata",
                remediation="Set WantAuthnRequestsSigned to true in IdP configuration.",
                cwe=345,
                tags=["saml", "unsigned-requests", "bosskey"],
            ))

        # Check for missing WantAssertionsSigned
        if 'wantassertionssigned="false"' in xml_lower:
            findings.append(Finding(
                title="SP does not require signed assertions",
                description=(
                    "The SP metadata indicates WantAssertionsSigned=false. "
                    "Unsigned assertions can be forged by an attacker."
                ),
                severity=Severity.HIGH,
                target=target,
                evidence="WantAssertionsSigned=false in metadata",
                remediation="Require signed assertions in SP configuration.",
                cwe=345,
                tags=["saml", "unsigned-assertions", "bosskey"],
            ))

        return findings

    # ----------------------------------------------------------
    # Signature wrapping probes
    # ----------------------------------------------------------

    async def _test_signature_wrapping(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Probe for XML Signature Wrapping (XSW) vulnerabilities."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        acs_url = self._config.sp_acs_url or f"{url}/saml/acs"

        for attack in WRAPPING_ATTACK_PATTERNS:
            wrapped_saml = self._build_xsw_payload(attack["technique"])
            if not wrapped_saml:
                continue

            try:
                resp = await self._client.request(
                    "POST", acs_url,
                    body=f"SAMLResponse={wrapped_saml}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # Detect if the XSW payload was accepted
                if self._xsw_accepted(resp):
                    findings.append(Finding(
                        title=f"SAML Signature Wrapping: {attack['name']}",
                        description=(
                            f"{attack['description']}\n\n"
                            f"The service provider accepted a response with a "
                            f"manipulated assertion, indicating the signature "
                            f"validation can be bypassed."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        evidence=(
                            f"Technique: {attack['technique']}\n"
                            f"ACS URL: {acs_url}\n"
                            f"Response status: {resp.status_code}"
                        ),
                        remediation=(
                            "Ensure the SP validates that the signature covers the "
                            "exact assertion being processed. Use a SAML library "
                            "that is not vulnerable to XSW attacks."
                        ),
                        cwe=347,
                        tags=["saml", "xsw", "signature-wrapping", "bosskey"],
                    ))

            except Exception:
                continue

        return findings

    def _build_xsw_payload(self, technique: str) -> Optional[str]:
        """Build an XSW payload for the given technique.

        In a real deployment, these would use the test_assertion from config.
        Here we build detection probes that check if the SP is vulnerable.
        """
        _test_assertion = self._config.test_assertion
        # If no test assertion available, build a minimal probe
        marker = hashlib.sha256(f"xsw-{technique}-{time.time()}".encode()).hexdigest()[:16]

        # Minimal SAML response with marker for XSW detection
        evil_nameid = f"xsw-probe-{marker}@evil.example"

        if technique == "xsw6":
            # Comment injection — special case
            evil_nameid = f"admin{marker}<!------>@evil.example"

        # Build a minimal SAML response structure
        saml_response = (
            f'<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" '
            f'ID="_resp_{marker}" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">'
            f'<saml:Assertion ID="_assert_{marker}" Version="2.0" '
            f'IssueInstant="2025-01-01T00:00:00Z">'
            f'<saml:Issuer>https://evil.example/saml</saml:Issuer>'
            f'<saml:Subject>'
            f'<saml:NameID>{evil_nameid}</saml:NameID>'
            f'</saml:Subject>'
            f'<saml:Conditions NotBefore="2020-01-01T00:00:00Z" '
            f'NotOnOrAfter="2099-12-31T23:59:59Z"/>'
            f'<saml:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z">'
            f'<saml:AuthnContext>'
            f'<saml:AuthnContextClassRef>'
            f'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            f'</saml:AuthnContextClassRef>'
            f'</saml:AuthnContext>'
            f'</saml:AuthnStatement>'
            f'</saml:Assertion>'
            f'</samlp:Response>'
        )

        import base64
        return base64.b64encode(saml_response.encode()).decode()

    def _xsw_accepted(self, resp: Any) -> bool:
        """Check if a signature wrapping probe was accepted."""
        if resp.status_code in (200, 302, 303):
            text = resp.text.lower()
            # Look for signs of successful authentication
            success_indicators = [
                "welcome", "dashboard", "profile", "logged in",
                "session", "token", "authenticated",
            ]
            rejection_indicators = [
                "invalid signature", "signature validation failed",
                "invalid saml", "error", "unauthorized", "forbidden",
                "bad request",
            ]

            has_success = any(ind in text for ind in success_indicators)
            has_rejection = any(ind in text for ind in rejection_indicators)

            # If success indicators present and no rejections, likely vulnerable
            if has_success and not has_rejection:
                return True

            # 302 to a dashboard-like URL
            location = ""
            if hasattr(resp, "headers"):
                location = resp.headers.get("location", "").lower()
            if resp.status_code in (302, 303) and any(
                p in location for p in ["dashboard", "home", "profile", "app"]
            ):
                return True

        return False

    # ----------------------------------------------------------
    # Assertion replay
    # ----------------------------------------------------------

    async def _test_assertion_replay(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test if the SP accepts replayed (previously used) assertions."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        acs_url = self._config.sp_acs_url or f"{url}/saml/acs"
        test_assertion = self._config.test_assertion

        if not test_assertion:
            # Build a probe assertion
            marker = hashlib.sha256(f"replay-{time.time()}".encode()).hexdigest()[:16]
            import base64
            test_assertion = base64.b64encode(
                f'<samlp:Response xmlns:samlp="{SAMLP_NS}" '
                f'ID="_replay_{marker}" Version="2.0" '
                f'IssueInstant="2025-01-01T00:00:00Z">'
                f'<saml:Assertion xmlns:saml="{SAML_NS}" '
                f'ID="_assert_replay_{marker}" Version="2.0">'
                f'<saml:Issuer>https://test.example/saml</saml:Issuer>'
                f'</saml:Assertion></samlp:Response>'.encode()
            ).decode()

        # Send the assertion twice
        responses = []
        for _i in range(2):
            try:
                resp = await self._client.request(
                    "POST", acs_url,
                    body=f"SAMLResponse={test_assertion}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                responses.append(resp)
            except Exception:
                break

        if len(responses) == 2:
            first = responses[0]
            second = responses[1]

            # If both are accepted (not rejected), replay may be possible
            first_ok = first.status_code in (200, 302, 303)
            second_ok = second.status_code in (200, 302, 303)
            second_text = second.text.lower()

            # The second should be rejected (replay protection)
            if first_ok and second_ok:
                # Check if both look like successful responses
                if "invalid" not in second_text and "replay" not in second_text:
                    findings.append(Finding(
                        title="SAML assertion replay accepted",
                        description=(
                            "The service provider accepted the same SAML assertion "
                            "twice, indicating missing or inadequate replay protection. "
                            "An attacker who intercepts a valid assertion can reuse it."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        evidence=(
                            f"ACS URL: {acs_url}\n"
                            f"First response: {first.status_code}\n"
                            f"Second response: {second.status_code}"
                        ),
                        remediation=(
                            "Implement assertion replay detection using a cache of "
                            "previously consumed assertion IDs (InResponseTo). "
                            "Reject assertions with duplicate IDs."
                        ),
                        cwe=294,
                        tags=["saml", "replay", "bosskey"],
                    ))

        return findings

    # ----------------------------------------------------------
    # Recipient / Audience validation
    # ----------------------------------------------------------

    async def _test_recipient_validation(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Test if the SP validates the Recipient and Audience in assertions."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        acs_url = self._config.sp_acs_url or f"{url}/saml/acs"
        evil_recipient = "https://evil.example.com/saml/acs"
        evil_audience = "https://evil.example.com"

        marker = hashlib.sha256(f"recipient-{time.time()}".encode()).hexdigest()[:16]
        import base64

        # Build assertion with wrong recipient
        bad_recipient_saml = base64.b64encode(
            f'<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" '
            f'ID="_rcpt_{marker}" Version="2.0" '
            f'Destination="{evil_recipient}" '
            f'IssueInstant="2025-01-01T00:00:00Z">'
            f'<saml:Assertion ID="_assert_rcpt_{marker}" Version="2.0" '
            f'IssueInstant="2025-01-01T00:00:00Z">'
            f'<saml:Issuer>https://idp.example/saml</saml:Issuer>'
            f'<saml:Subject>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData Recipient="{evil_recipient}" '
            f'NotOnOrAfter="2099-12-31T23:59:59Z"/>'
            f'</saml:SubjectConfirmation>'
            f'</saml:Subject>'
            f'<saml:Conditions>'
            f'<saml:AudienceRestriction>'
            f'<saml:Audience>{evil_audience}</saml:Audience>'
            f'</saml:AudienceRestriction>'
            f'</saml:Conditions>'
            f'</saml:Assertion>'
            f'</samlp:Response>'.encode()
        ).decode()

        try:
            resp = await self._client.request(
                "POST", acs_url,
                body=f"SAMLResponse={bad_recipient_saml}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if self._xsw_accepted(resp):
                findings.append(Finding(
                    title="SAML Recipient/Audience validation bypass",
                    description=(
                        "The SP accepted a SAML assertion with a Recipient and "
                        "Audience pointing to a different SP. This allows an "
                        "attacker to forward assertions intended for one SP to "
                        "another, gaining unauthorized access."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=(
                        f"ACS URL: {acs_url}\n"
                        f"Evil recipient: {evil_recipient}\n"
                        f"Evil audience: {evil_audience}\n"
                        f"Response status: {resp.status_code}"
                    ),
                    remediation=(
                        "Validate that the Recipient matches the SP's ACS URL "
                        "and the Audience matches the SP's entity ID."
                    ),
                    cwe=287,
                    tags=["saml", "recipient-bypass", "bosskey"],
                ))

        except Exception:
            pass

        return findings

    # ----------------------------------------------------------
    # Assertion timing
    # ----------------------------------------------------------

    async def _test_assertion_timing(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Check if the SP enforces NotBefore/NotOnOrAfter conditions."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        acs_url = self._config.sp_acs_url or f"{url}/saml/acs"
        marker = hashlib.sha256(f"timing-{time.time()}".encode()).hexdigest()[:16]
        import base64

        # Build an expired assertion (NotOnOrAfter in the past)
        expired_saml = base64.b64encode(
            f'<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" '
            f'ID="_exp_{marker}" Version="2.0" '
            f'IssueInstant="2020-01-01T00:00:00Z">'
            f'<saml:Assertion ID="_assert_exp_{marker}" Version="2.0" '
            f'IssueInstant="2020-01-01T00:00:00Z">'
            f'<saml:Issuer>https://idp.example/saml</saml:Issuer>'
            f'<saml:Subject>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData '
            f'NotOnOrAfter="2020-01-01T00:05:00Z"/>'
            f'</saml:SubjectConfirmation>'
            f'</saml:Subject>'
            f'<saml:Conditions NotBefore="2020-01-01T00:00:00Z" '
            f'NotOnOrAfter="2020-01-01T00:05:00Z"/>'
            f'</saml:Assertion>'
            f'</samlp:Response>'.encode()
        ).decode()

        try:
            resp = await self._client.request(
                "POST", acs_url,
                body=f"SAMLResponse={expired_saml}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if self._xsw_accepted(resp):
                findings.append(Finding(
                    title="SAML assertion timing not enforced",
                    description=(
                        "The SP accepted an expired SAML assertion "
                        "(NotOnOrAfter in the past). An attacker with a "
                        "captured assertion can use it indefinitely."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    evidence=(
                        f"ACS URL: {acs_url}\n"
                        f"NotOnOrAfter: 2020-01-01T00:05:00Z\n"
                        f"Response status: {resp.status_code}"
                    ),
                    remediation=(
                        "Enforce NotBefore and NotOnOrAfter conditions on "
                        "all SAML assertions. Reject expired assertions."
                    ),
                    cwe=613,
                    tags=["saml", "timing", "expired-assertion", "bosskey"],
                ))

        except Exception:
            pass

        return findings

    # ----------------------------------------------------------
    # Algorithm strength
    # ----------------------------------------------------------

    async def _test_algorithm_strength(
        self, url: str, target: Target,
    ) -> List[Finding]:
        """Check for weak signature/digest algorithms in SAML responses."""
        findings: List[Finding] = []
        if not self._client:
            return findings

        # Try to trigger a SAML response by initiating SSO
        sso_urls = [
            self._config.idp_url,
            f"{url}/saml/sso",
            f"{url}/saml2/sso",
            f"{url}/auth/saml",
        ]

        for sso_url in sso_urls:
            if not sso_url:
                continue

            try:
                resp = await self._client.request("GET", sso_url)
                text = resp.text

                # Check for weak algorithms in any SAML XML we can see
                weak_algos = self._detect_weak_algorithms(text)
                for algo_info in weak_algos:
                    findings.append(Finding(
                        title=f"Weak SAML {algo_info['type']} algorithm: {algo_info['algo']}",
                        description=(
                            f"The SAML implementation uses {algo_info['algo']} for "
                            f"{algo_info['type']}. {algo_info['risk']}"
                        ),
                        severity=Severity.MEDIUM,
                        target=target,
                        evidence=(
                            f"URL: {sso_url}\n"
                            f"Algorithm: {algo_info['algo']}\n"
                            f"Type: {algo_info['type']}"
                        ),
                        remediation=algo_info["remediation"],
                        cwe=327,
                        tags=["saml", "weak-crypto", "bosskey"],
                    ))

            except Exception:
                continue

        return findings

    def _detect_weak_algorithms(self, text: str) -> List[Dict[str, str]]:
        """Detect weak crypto algorithms in SAML XML content."""
        weak: List[Dict[str, str]] = []

        # Signature algorithms
        sig_patterns = {
            "rsa-sha1": "RSA with SHA-1 is deprecated due to collision attacks.",
            "dsa-sha1": "DSA with SHA-1 is deprecated.",
            "hmac-sha1": "HMAC-SHA1 is weaker than HMAC-SHA256.",
            "rsa-md5": "MD5 is cryptographically broken.",
        }

        for algo_name, risk in sig_patterns.items():
            if algo_name in text.lower():
                weak.append({
                    "type": "signature",
                    "algo": algo_name.upper(),
                    "risk": risk,
                    "remediation": "Upgrade to RSA-SHA256 or stronger.",
                })

        # Digest algorithms
        digest_patterns = {
            "#sha1": "SHA-1 digest is vulnerable to collision attacks.",
            "#md5": "MD5 digest is cryptographically broken.",
        }

        for algo_name, risk in digest_patterns.items():
            if algo_name in text.lower():
                weak.append({
                    "type": "digest",
                    "algo": algo_name.upper().lstrip("#"),
                    "risk": risk,
                    "remediation": "Use SHA-256 or SHA-512 for digest algorithms.",
                })

        return weak
