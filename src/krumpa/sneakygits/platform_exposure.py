"""
SneakyGits — platform and public admin surface exposure analysis.

Performs safe, read-only checks for publicly reachable Kubernetes,
container, and operational admin surfaces.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from krumpa.core import Finding, Severity, Target
from krumpa.core.http_client import HttpClient, HttpClientMixin

logger = logging.getLogger("krumpa.sneakygits.platform_exposure")


@dataclass(frozen=True)
class PlatformProbe:
    """Definition of a safe management-surface probe."""

    product: str
    category: str
    path: str
    body_patterns: Tuple[str, ...] = ()
    header_patterns: Dict[str, str] = field(default_factory=dict)
    exposed_severity: Severity = Severity.MEDIUM
    protected_severity: Severity = Severity.INFO
    cwe: Optional[int] = 200
    tags: Tuple[str, ...] = ()
    hint_keywords: Tuple[str, ...] = ()
    protected_redirect_keywords: Tuple[str, ...] = ("login", "signin", "auth", "oauth")


@dataclass
class ProbeMatch:
    """Observed match for a single probe."""

    probe: PlatformProbe
    status_code: int
    url: str
    evidence: str
    exposed: bool


_PLATFORM_PROBES: Tuple[PlatformProbe, ...] = (
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/version",
        body_patterns=('"gitVersion"', '"major"', '"minor"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "kubernetes", "control-plane"),
        hint_keywords=("kube", "k8s", "cluster", "api", "control-plane"),
    ),
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/api",
        body_patterns=('"kind":"APIVersions"', '"versions"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "control-plane"),
        hint_keywords=("kube", "k8s", "cluster", "api", "control-plane"),
    ),
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/apis",
        body_patterns=('"kind":"APIGroupList"', '"groups"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "control-plane"),
        hint_keywords=("kube", "k8s", "cluster", "api", "control-plane"),
    ),
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/healthz",
        body_patterns=("ok",),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "kubernetes", "control-plane", "health"),
        hint_keywords=("kube", "k8s", "cluster", "health", "api"),
    ),
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/livez",
        body_patterns=("ok",),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "kubernetes", "control-plane", "health"),
        hint_keywords=("kube", "k8s", "cluster", "health", "api"),
    ),
    PlatformProbe(
        product="Kubernetes API server",
        category="kubernetes",
        path="/readyz",
        body_patterns=("ok",),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "kubernetes", "control-plane", "health"),
        hint_keywords=("kube", "k8s", "cluster", "health", "api"),
    ),
    PlatformProbe(
        product="Kubelet",
        category="kubernetes",
        path="/pods",
        body_patterns=('"kind":"PodList"',),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "kubelet"),
        hint_keywords=("kubelet", "node", "worker", "kube", "k8s"),
    ),
    PlatformProbe(
        product="Kubelet",
        category="kubernetes",
        path="/metrics",
        body_patterns=("kubelet_", "rest_client_", "container_"),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "kubernetes", "kubelet", "metrics"),
        hint_keywords=("kubelet", "node", "worker", "kube", "k8s", "metrics"),
    ),
    PlatformProbe(
        product="Kubelet",
        category="kubernetes",
        path="/stats/summary",
        body_patterns=('"node"', '"pods"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "kubelet", "metrics"),
        hint_keywords=("kubelet", "node", "worker", "kube", "k8s", "metrics"),
    ),
    PlatformProbe(
        product="Kubelet",
        category="kubernetes",
        path="/debug/pprof/",
        body_patterns=("types of profiles available", "/debug/pprof/heap", "goroutine"),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "kubernetes", "kubelet", "debug"),
        hint_keywords=("kubelet", "node", "worker", "kube", "k8s", "debug"),
    ),
    PlatformProbe(
        product="Kubernetes Dashboard",
        category="kubernetes",
        path="/api/v1/csrftoken/login",
        body_patterns=('"token"',),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "kubernetes", "dashboard"),
        hint_keywords=("dashboard", "kube", "k8s", "cluster"),
    ),
    PlatformProbe(
        product="Kubernetes Dashboard",
        category="kubernetes",
        path="/api/v1/settings/global",
        body_patterns=('"clusterName"', '"itemsPerPage"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "kubernetes", "dashboard"),
        hint_keywords=("dashboard", "kube", "k8s", "cluster"),
    ),
    PlatformProbe(
        product="etcd",
        category="kubernetes",
        path="/version",
        body_patterns=('"etcdserver"', '"etcdcluster"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "etcd"),
        hint_keywords=("etcd", "kube", "k8s", "cluster"),
    ),
    PlatformProbe(
        product="etcd",
        category="kubernetes",
        path="/v2/keys/?recursive=true",
        body_patterns=('"action"', '"node"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "kubernetes", "etcd"),
        hint_keywords=("etcd", "kube", "k8s", "cluster"),
    ),
    PlatformProbe(
        product="Docker Engine API",
        category="container",
        path="/version",
        body_patterns=('"ApiVersion"', '"Version"', '"GoVersion"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "docker", "container-api"),
        hint_keywords=("docker", "container", "engine", "api"),
    ),
    PlatformProbe(
        product="Docker Engine API",
        category="container",
        path="/info",
        body_patterns=('"Containers"', '"Driver"', '"ServerVersion"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "docker", "container-api"),
        hint_keywords=("docker", "container", "engine", "api"),
    ),
    PlatformProbe(
        product="Docker Engine API",
        category="container",
        path="/containers/json",
        body_patterns=('"Image"', '"State"', '"Command"'),
        exposed_severity=Severity.CRITICAL,
        tags=("platform-exposure", "docker", "container-api"),
        hint_keywords=("docker", "container", "engine", "api"),
    ),
    PlatformProbe(
        product="Docker Registry",
        category="container",
        path="/v2/_catalog",
        body_patterns=('"repositories"',),
        header_patterns={"Docker-Distribution-Api-Version": r"registry/2\.0"},
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "docker", "registry"),
        hint_keywords=("registry", "docker", "artifact", "harbor"),
    ),
    PlatformProbe(
        product="Docker Registry",
        category="container",
        path="/v2/",
        header_patterns={"Docker-Distribution-Api-Version": r"registry/2\.0"},
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "docker", "registry"),
        hint_keywords=("registry", "docker", "artifact", "harbor"),
    ),
    PlatformProbe(
        product="Portainer",
        category="container",
        path="/api/status",
        body_patterns=('"Version"', '"Edition"'),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "portainer", "admin-surface"),
        hint_keywords=("portainer", "docker", "container"),
    ),
    PlatformProbe(
        product="Harbor",
        category="container",
        path="/api/v2.0/systeminfo",
        body_patterns=('"harbor_version"', '"registry_url"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "harbor", "registry", "admin-surface"),
        hint_keywords=("harbor", "registry", "artifact"),
    ),
    PlatformProbe(
        product="Quay",
        category="container",
        path="/api/v1/discovery",
        body_patterns=("quay", "docker", "repository"),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "quay", "registry", "admin-surface"),
        hint_keywords=("quay", "registry", "artifact"),
    ),
    PlatformProbe(
        product="Artifactory",
        category="container",
        path="/artifactory/api/system/version",
        body_patterns=("version", "revision"),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "artifactory", "registry", "admin-surface"),
        hint_keywords=("artifactory", "registry", "artifact", "jfrog"),
    ),
    PlatformProbe(
        product="Argo CD",
        category="kubernetes",
        path="/api/v1/settings",
        body_patterns=('"url"', '"dexConfig"', '"statusBadgeEnabled"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "argocd", "kubernetes", "admin-surface"),
        hint_keywords=("argo", "argocd", "gitops", "kube", "k8s"),
    ),
    PlatformProbe(
        product="Prometheus",
        category="admin",
        path="/api/v1/status/buildinfo",
        body_patterns=('"status":"success"', '"revision"', '"version"'),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "prometheus", "admin-surface"),
        hint_keywords=("prometheus", "metrics", "monitor"),
    ),
    PlatformProbe(
        product="Grafana",
        category="admin",
        path="/api/health",
        body_patterns=('"database":"ok"', '"version"'),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "grafana", "admin-surface"),
        hint_keywords=("grafana", "dashboard", "monitor"),
    ),
    PlatformProbe(
        product="Elasticsearch",
        category="admin",
        path="/",
        body_patterns=('"cluster_name"', '"tagline"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "elasticsearch", "admin-surface"),
        hint_keywords=("elastic", "elasticsearch", "search"),
    ),
    PlatformProbe(
        product="Elasticsearch",
        category="admin",
        path="/_cluster/health",
        body_patterns=('"cluster_name"', '"status"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "elasticsearch", "admin-surface"),
        hint_keywords=("elastic", "elasticsearch", "search"),
    ),
    PlatformProbe(
        product="Kibana",
        category="admin",
        path="/api/status",
        body_patterns=('"overall"', '"statuses"', '"Kibana"'),
        exposed_severity=Severity.MEDIUM,
        tags=("platform-exposure", "kibana", "admin-surface"),
        hint_keywords=("kibana", "elastic", "dashboard"),
    ),
    PlatformProbe(
        product="RabbitMQ Management",
        category="admin",
        path="/api/overview",
        body_patterns=('"rabbitmq_version"', '"cluster_name"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "rabbitmq", "admin-surface"),
        hint_keywords=("rabbitmq", "mq", "queue"),
    ),
    PlatformProbe(
        product="Jenkins",
        category="admin",
        path="/api/json",
        body_patterns=('"jobs"', '"views"', '"mode"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "jenkins", "admin-surface"),
        hint_keywords=("jenkins", "ci", "build"),
    ),
    PlatformProbe(
        product="Consul",
        category="admin",
        path="/v1/agent/self",
        body_patterns=('"Config"', '"Datacenter"', '"NodeName"'),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "consul", "admin-surface"),
        hint_keywords=("consul", "service-discovery"),
    ),
    PlatformProbe(
        product="Nomad",
        category="admin",
        path="/v1/status/leader",
        body_patterns=(":4647",),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "nomad", "admin-surface"),
        hint_keywords=("nomad", "scheduler", "hashicorp"),
    ),
    PlatformProbe(
        product="Rancher",
        category="kubernetes",
        path="/v3/settings/server-url",
        body_patterns=("server-url", "value"),
        exposed_severity=Severity.HIGH,
        tags=("platform-exposure", "rancher", "kubernetes", "admin-surface"),
        hint_keywords=("rancher", "cluster", "kube", "k8s"),
    ),
)


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PlatformExposureAnalyzer(HttpClientMixin):
    """Analyze targets for exposed Kubernetes, container, and admin surfaces."""

    def __init__(self, *, http_client: Optional[HttpClient] = None) -> None:
        self._client = http_client
        self._owns_client = http_client is None

    async def analyze(self, target: Target) -> List[Finding]:
        if not self._client:
            return []

        base = self._base_url(target.url)
        matches: List[ProbeMatch] = []
        selected_probes = self._select_probes(target)

        for probe in selected_probes:
            probe_url = f"{base}{probe.path}"
            try:
                resp = await self._client.request("GET", probe_url)
            except Exception as exc:
                logger.debug("Platform exposure probe failed for %s: %s", probe_url, exc)
                continue

            matched, evidence = self._match_probe(resp, probe)
            if not matched:
                continue

            exposed = resp.status_code == 200
            matches.append(ProbeMatch(
                probe=probe,
                status_code=resp.status_code,
                url=probe_url,
                evidence=evidence,
                exposed=exposed,
            ))

        return self._build_findings(target, matches)

    def _select_probes(self, target: Target) -> Tuple[PlatformProbe, ...]:
        host = target.host.lower()
        path = urlparse(target.url).path.lower()
        tokens = self._hint_tokens(target)

        selected: List[PlatformProbe] = []
        for probe in _PLATFORM_PROBES:
            if self._probe_matches_hints(probe, host, path, tokens):
                selected.append(probe)

        if not selected:
            # Fallback to a compact generic baseline when there are no hints.
            selected = [
                probe for probe in _PLATFORM_PROBES
                if probe.product in {
                    "Kubernetes API server",
                    "Kubelet",
                    "Docker Engine API",
                    "Docker Registry",
                    "Portainer",
                    "Harbor",
                    "Prometheus",
                    "Grafana",
                    "Elasticsearch",
                    "RabbitMQ Management",
                    "Jenkins",
                }
            ]

        return tuple(selected)

    @staticmethod
    def _hint_tokens(target: Target) -> set[str]:
        tokens: set[str] = set()
        for key in ("fingerprint_techs", "fingerprint_db_techs"):
            value = target.metadata.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        tokens.update(re.findall(r"[a-z0-9]+", item.lower()))
        return tokens

    @staticmethod
    def _probe_matches_hints(
        probe: PlatformProbe,
        host: str,
        path: str,
        tokens: set[str],
    ) -> bool:
        if not probe.hint_keywords:
            return True

        haystack = f"{host} {path}"
        for hint in probe.hint_keywords:
            hint_lower = hint.lower()
            if hint_lower in haystack or hint_lower in tokens:
                return True

        return False

    @staticmethod
    def _base_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _match_probe(resp, probe: PlatformProbe) -> tuple[bool, str]:
        status = getattr(resp, "status_code", 0)
        text = getattr(resp, "text", "") or ""
        headers = getattr(resp, "headers", {}) or {}
        location = PlatformExposureAnalyzer._get_header(headers, "location")

        header_evidence = PlatformExposureAnalyzer._match_headers(headers, probe.header_patterns)
        body_evidence = PlatformExposureAnalyzer._match_body(text, probe.body_patterns)

        if status == 200 and (header_evidence or body_evidence):
            return True, header_evidence or body_evidence

        if status in (401, 403) and (header_evidence or body_evidence):
            return True, header_evidence or body_evidence

        if status in (301, 302, 303, 307, 308) and location:
            lower_location = location.lower()
            for keyword in probe.protected_redirect_keywords:
                if keyword in lower_location:
                    return True, f"redirect location={location}"

        return False, ""

    @staticmethod
    def _get_header(headers: Dict[str, str], name: str) -> str:
        for actual_name, actual_value in headers.items():
            if actual_name.lower() == name.lower():
                return actual_value
        return ""

    @staticmethod
    def _match_headers(headers: Dict[str, str], patterns: Dict[str, str]) -> str:
        for expected_name, pattern in patterns.items():
            for actual_name, actual_value in headers.items():
                if actual_name.lower() != expected_name.lower():
                    continue
                if re.search(pattern, actual_value, re.IGNORECASE):
                    return f"header {actual_name}={actual_value}"
        return ""

    @staticmethod
    def _match_body(text: str, patterns: Tuple[str, ...]) -> str:
        lower = text.lower()
        for pattern in patterns:
            if pattern.lower() in lower:
                return f"body contains '{pattern}'"
        return ""

    def _build_findings(self, target: Target, matches: List[ProbeMatch]) -> List[Finding]:
        findings: List[Finding] = []
        grouped: Dict[tuple[str, bool], List[ProbeMatch]] = {}

        for match in matches:
            grouped.setdefault((match.probe.product, match.exposed), []).append(match)

        for (product, exposed), product_matches in grouped.items():
            probe = product_matches[0].probe
            if exposed:
                severity = self._max_severity(m.probe.exposed_severity for m in product_matches)
                title = f"{product} management surface exposed"
                description = (
                    f"Publicly reachable {product} endpoints were detected on {target.host}. "
                    f"This exposes operational or orchestration interfaces that should not be internet-facing."
                )
                remediation = (
                    "Remove public access to management and orchestration endpoints. "
                    "Restrict exposure with network policy, authentication, and gateway rules."
                )
            else:
                severity = self._max_severity(m.probe.protected_severity for m in product_matches)
                title = f"Protected {product} management surface discovered"
                description = (
                    f"{product} endpoints were discovered on {target.host} and appear to require authentication. "
                    f"This is informational but expands the attack surface and should be intentionally exposed only where required."
                )
                remediation = (
                    "Keep management endpoints behind authentication and, where possible, "
                    "restrict them to private networks or administrative access paths."
                )

            evidence_lines = [
                f"{m.url} -> {m.status_code} ({m.evidence})"
                for m in sorted(product_matches, key=lambda item: item.url)
            ]
            tags = sorted({tag for m in product_matches for tag in m.probe.tags})

            findings.append(Finding(
                title=title,
                description=description,
                severity=severity,
                target=target,
                evidence="\n".join(evidence_lines),
                remediation=remediation,
                cwe=probe.cwe,
                tags=tags,
            ))

        return findings

    @staticmethod
    def _max_severity(severities) -> Severity:
        best = Severity.INFO
        for severity in severities:
            if _SEVERITY_RANK[severity] > _SEVERITY_RANK[best]:
                best = severity
        return best