"""
Response fingerprinting — cluster HTTP responses by structural
similarity to reduce noise, detect anomalies, and group
unique error/success patterns.

Uses Levenshtein-inspired structural diffing on response body
structure (tag skeleton, JSON key shapes) rather than raw text.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from krumpa.core import Finding, Severity, Target

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Response fingerprint representation
# ------------------------------------------------------------------

@dataclass
class ResponseFingerprint:
    """Compact representation of an HTTP response for clustering."""
    status_code: int
    content_length: int
    content_type: str
    header_keys: Tuple[str, ...]
    body_hash: str                   # SHA-256 of full body
    structure_hash: str              # SHA-256 of structural skeleton
    word_count: int
    line_count: int

    @property
    def cluster_key(self) -> str:
        """Primary grouping key — status + structure hash."""
        return f"{self.status_code}:{self.structure_hash}"


@dataclass
class ResponseCluster:
    """A group of similar responses."""
    cluster_id: str
    representative: ResponseFingerprint
    members: List[ResponseFingerprint] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)


# ------------------------------------------------------------------
# Structural extraction helpers
# ------------------------------------------------------------------

# HTML tag skeleton extractor
_TAG_RE = re.compile(r'</?([a-zA-Z][a-zA-Z0-9]*)[^>]*/?>')

# JSON key extractor
_JSON_KEY_RE = re.compile(r'"([^"]+)"\s*:')


def _extract_html_skeleton(body: str) -> str:
    """Extract ordered tag names as a structural skeleton."""
    tags = _TAG_RE.findall(body)
    return ">".join(t.lower() for t in tags[:200])  # cap at 200 tags


def _extract_json_skeleton(body: str) -> str:
    """Extract JSON key structure as a skeleton."""
    try:
        data = json.loads(body)
        return _json_shape(data, depth=0, max_depth=5)
    except (json.JSONDecodeError, ValueError):
        # Fall back to regex key extraction
        keys = _JSON_KEY_RE.findall(body)
        return ",".join(keys[:100])


def _json_shape(obj: object, depth: int, max_depth: int) -> str:
    """Recursive JSON shape descriptor."""
    if depth >= max_depth:
        return "..."
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        parts = [f"{k}:{_json_shape(obj[k], depth + 1, max_depth)}" for k in keys[:20]]
        return "{" + ",".join(parts) + "}"
    if isinstance(obj, list):
        if not obj:
            return "[]"
        # Use first element as representative
        return f"[{_json_shape(obj[0], depth + 1, max_depth)}]"
    if isinstance(obj, str):
        return "s"
    if isinstance(obj, bool):
        return "b"
    if isinstance(obj, (int, float)):
        return "n"
    if obj is None:
        return "null"
    return "?"


def _extract_structure(body: str, content_type: str) -> str:
    """Choose extraction strategy based on content-type."""
    ct_lower = content_type.lower()
    if "json" in ct_lower:
        return _extract_json_skeleton(body)
    if "html" in ct_lower or "xml" in ct_lower:
        return _extract_html_skeleton(body)
    # Plain text — use line-count + word-count bucket
    lines = body.count("\n")
    words = len(body.split())
    return f"lines:{lines // 10 * 10},words:{words // 50 * 50}"


# ------------------------------------------------------------------
# Similarity scoring
# ------------------------------------------------------------------

def _jaccard_similarity(a: str, b: str) -> float:
    """Jaccard similarity on character trigrams."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    trigrams_a = {a[i:i+3] for i in range(len(a) - 2)}
    trigrams_b = {b[i:i+3] for i in range(len(b) - 2)}
    if not trigrams_a and not trigrams_b:
        return 1.0
    intersection = trigrams_a & trigrams_b
    union = trigrams_a | trigrams_b
    return len(intersection) / len(union) if union else 1.0


# ------------------------------------------------------------------
# Main fingerprinting engine
# ------------------------------------------------------------------

class ResponseFingerprinter:
    """
    Collects response fingerprints, clusters by structural similarity,
    and identifies anomalous responses that warrant investigation.
    """

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        self._fingerprints: List[Tuple[str, ResponseFingerprint]] = []  # (url, fp)
        self._clusters: Dict[str, ResponseCluster] = {}
        self._threshold = similarity_threshold

    def fingerprint(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> ResponseFingerprint:
        """Create a fingerprint from a raw response and store it."""
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        header_keys = tuple(sorted(k.lower() for k in headers))
        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]

        structure = _extract_structure(body, content_type)
        structure_hash = hashlib.sha256(structure.encode()).hexdigest()[:16]

        fp = ResponseFingerprint(
            status_code=status_code,
            content_length=len(body),
            content_type=content_type.split(";")[0].strip(),
            header_keys=header_keys,
            body_hash=body_hash,
            structure_hash=structure_hash,
            word_count=len(body.split()),
            line_count=body.count("\n") + 1,
        )

        self._fingerprints.append((url, fp))
        self._add_to_cluster(url, fp)

        return fp

    def _add_to_cluster(self, url: str, fp: ResponseFingerprint) -> None:
        """Add fingerprint to an existing or new cluster."""
        key = fp.cluster_key
        if key in self._clusters:
            self._clusters[key].members.append(fp)
            self._clusters[key].urls.append(url)
        else:
            self._clusters[key] = ResponseCluster(
                cluster_id=key,
                representative=fp,
                members=[fp],
                urls=[url],
            )

    def get_clusters(self) -> List[ResponseCluster]:
        """Return all clusters sorted by size (largest first)."""
        return sorted(self._clusters.values(), key=lambda c: c.size, reverse=True)

    def get_anomalies(self, min_cluster_size: int = 3) -> List[Tuple[str, ResponseFingerprint]]:
        """
        Find responses that don't fit into any significant cluster —
        potential indicators of interesting behavior.
        """
        anomalies: List[Tuple[str, ResponseFingerprint]] = []
        large_clusters = {k for k, c in self._clusters.items() if c.size >= min_cluster_size}

        for url, fp in self._fingerprints:
            if fp.cluster_key not in large_clusters:
                anomalies.append((url, fp))

        return anomalies

    def get_unique_responses(self) -> List[Tuple[str, ResponseFingerprint]]:
        """Return responses that have unique body hashes."""
        seen_hashes: set[str] = set()
        unique: List[Tuple[str, ResponseFingerprint]] = []

        for url, fp in self._fingerprints:
            if fp.body_hash not in seen_hashes:
                seen_hashes.add(fp.body_hash)
                unique.append((url, fp))

        return unique

    def analyze(self, targets: Sequence[Target]) -> List[Finding]:
        """
        Analyze stored fingerprints and produce findings about
        anomalous patterns, custom error pages, and response diversity.
        """
        findings: List[Finding] = []

        clusters = self.get_clusters()
        if not clusters:
            return findings

        # 1. Detect custom vs. generic error pages
        error_clusters = [c for c in clusters if c.representative.status_code >= 400]
        if error_clusters:
            unique_error_bodies = len({c.representative.body_hash for c in error_clusters})
            if unique_error_bodies == 1 and len(error_clusters) > 1:
                findings.append(Finding(
                    title="Generic error page across all error codes",
                    description=(
                        f"All {len(error_clusters)} error response patterns share the same "
                        f"body content. A uniform error page may leak less information but "
                        f"also suggests a custom error handler is in place."
                    ),
                    severity=Severity.INFO,
                    evidence=f"Unique error bodies: {unique_error_bodies}",
                    remediation="Consider returning appropriate status codes with minimal info.",
                    cwe=209,
                    tags=["response-fingerprint", "error-page", "grotassault"],
                ))

        # 2. Detect anomalous responses (could be interesting endpoints)
        anomalies = self.get_anomalies()
        if anomalies:
            for url, fp in anomalies[:5]:  # Report up to 5
                findings.append(Finding(
                    title=f"Anomalous response at {url}",
                    description=(
                        f"Response from {url} has a unique structural pattern "
                        f"(status={fp.status_code}, structure={fp.structure_hash[:8]}) "
                        f"that doesn't match common response clusters."
                    ),
                    severity=Severity.INFO,
                    evidence=(
                        f"Status: {fp.status_code}\n"
                        f"Content-Type: {fp.content_type}\n"
                        f"Body hash: {fp.body_hash}\n"
                        f"Words: {fp.word_count}, Lines: {fp.line_count}"
                    ),
                    tags=["response-fingerprint", "anomaly", "grotassault"],
                ))

        # 3. Detect status code variety for same path pattern
        status_dist: Counter[int] = Counter()
        for _, fp in self._fingerprints:
            status_dist[fp.status_code] += 1

        unexpected_codes = {code for code in status_dist if code in (500, 502, 503)}
        if unexpected_codes:
            findings.append(Finding(
                title="Server error responses detected during fuzzing",
                description=(
                    f"Server returned error codes {sorted(unexpected_codes)} during testing. "
                    f"This may indicate unhandled exceptions or stability issues."
                ),
                severity=Severity.LOW,
                evidence=f"Status distribution: {dict(status_dist)}",
                remediation="Investigate server errors; ensure proper error handling.",
                cwe=209,
                tags=["response-fingerprint", "server-error", "grotassault"],
            ))

        return findings

    def summary(self) -> Dict[str, object]:
        """Return a summary of fingerprinting results."""
        clusters = self.get_clusters()
        return {
            "total_responses": len(self._fingerprints),
            "clusters": len(clusters),
            "largest_cluster": clusters[0].size if clusters else 0,
            "anomalies": len(self.get_anomalies()),
            "unique_bodies": len(self.get_unique_responses()),
        }
