"""Tests for platform and admin surface exposure analysis."""

from __future__ import annotations

import pytest

from krumpa.core import Severity, Target
from krumpa.sneakygits.platform_exposure import PlatformExposureAnalyzer


class FakeHeaders(dict):
    """dict subclass with case-insensitive matching helpers."""

    def items(self):
        return super().items()


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = FakeHeaders(headers or {})


class FakeHttpClient:
    """Route canned responses by absolute URL."""

    def __init__(self, routes: dict[str, FakeResponse]):
        self._routes = routes

    async def request(self, method: str, url: str, **kwargs):
        return self._routes.get(url, FakeResponse(status_code=404, text="not found"))

    async def close(self):
        pass


@pytest.mark.asyncio
class TestPlatformExposureAnalyzer:

    async def test_returns_empty_without_client(self):
        analyzer = PlatformExposureAnalyzer()
        findings = await analyzer.analyze(Target(url="https://example.com"))
        assert findings == []

    async def test_detects_exposed_kubernetes_api(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://example.com/version": FakeResponse(
                status_code=200,
                text='{"major":"1","minor":"29","gitVersion":"v1.29.2"}',
            ),
            "https://example.com/api": FakeResponse(
                status_code=200,
                text='{"kind":"APIVersions","versions":["v1"]}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://example.com/app"))

        assert len(findings) == 1
        assert "Kubernetes API server" in findings[0].title
        assert findings[0].severity == Severity.CRITICAL
        assert "https://example.com/api -> 200" in findings[0].evidence

    async def test_detects_protected_registry_surface(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://registry.example.com/v2/": FakeResponse(
                status_code=401,
                text="authentication required",
                headers={"Docker-Distribution-Api-Version": "registry/2.0"},
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://registry.example.com"))

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Protected Docker Registry" in findings[0].title

    async def test_detects_exposed_elasticsearch(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://search.example.com/": FakeResponse(
                status_code=200,
                text='{"name":"node-1","cluster_name":"prod-search","tagline":"You Know, for Search"}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://search.example.com/index.html"))

        assert len(findings) == 1
        assert "Elasticsearch" in findings[0].title
        assert findings[0].severity == Severity.HIGH

    async def test_ignores_non_matching_responses(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://example.com/version": FakeResponse(status_code=200, text="plain text version page"),
            "https://example.com/api": FakeResponse(status_code=200, text="generic api homepage"),
        }))

        findings = await analyzer.analyze(Target(url="https://example.com"))

        assert findings == []

    async def test_detects_kubernetes_dashboard_when_host_hint_matches(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://dashboard.example.com/api/v1/settings/global": FakeResponse(
                status_code=200,
                text='{"clusterName":"prod","itemsPerPage":10}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://dashboard.example.com"))

        assert len(findings) == 1
        assert "Kubernetes Dashboard" in findings[0].title

    async def test_detects_harbor_using_registry_hint(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://harbor.example.com/api/v2.0/systeminfo": FakeResponse(
                status_code=200,
                text='{"harbor_version":"2.10.0","registry_url":"harbor.example.com"}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://harbor.example.com"))

        assert len(findings) == 1
        assert "Harbor" in findings[0].title
        assert findings[0].severity == Severity.HIGH

    async def test_detects_quay_registry(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://quay.example.com/api/v1/discovery": FakeResponse(
                status_code=200,
                text='{"quay":true,"features":["docker","repository"]}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://quay.example.com"))

        assert len(findings) == 1
        assert "Quay" in findings[0].title

    async def test_detects_artifactory(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://artifactory.example.com/artifactory/api/system/version": FakeResponse(
                status_code=200,
                text='{"version":"7.77.3","revision":"77703"}',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://artifactory.example.com"))

        assert len(findings) == 1
        assert "Artifactory" in findings[0].title

    async def test_detects_kubelet_pprof_debug_surface(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://node-kubelet.example.com/debug/pprof/": FakeResponse(
                status_code=200,
                text='Types of profiles available:\n/debug/pprof/heap\n/debug/pprof/goroutine',
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://node-kubelet.example.com"))

        assert len(findings) == 1
        assert "Kubelet" in findings[0].title
        assert findings[0].severity == Severity.HIGH

    async def test_detects_kibana_when_fingerprint_metadata_exists(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://ops.example.com/api/status": FakeResponse(
                status_code=200,
                text='{"name":"kibana","overall":{"level":"available"},"statuses":[]}',
            ),
        }))

        findings = await analyzer.analyze(Target(
            url="https://ops.example.com",
            metadata={"fingerprint_db_techs": ["Kibana"]},
        ))

        assert len(findings) == 1
        assert "Kibana" in findings[0].title

    async def test_detects_protected_surface_via_redirect_to_login(self):
        analyzer = PlatformExposureAnalyzer(http_client=FakeHttpClient({
            "https://jenkins.example.com/api/json": FakeResponse(
                status_code=302,
                headers={"Location": "https://jenkins.example.com/login?from=%2Fapi%2Fjson"},
            ),
        }))

        findings = await analyzer.analyze(Target(url="https://jenkins.example.com"))

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Protected Jenkins" in findings[0].title
        assert "redirect location=" in findings[0].evidence

    async def test_routing_skips_irrelevant_probes_without_hints(self):
        calls: list[str] = []

        class TrackingClient(FakeHttpClient):
            async def request(self, method: str, url: str, **kwargs):
                calls.append(url)
                return await super().request(method, url, **kwargs)

        analyzer = PlatformExposureAnalyzer(http_client=TrackingClient({}))
        await analyzer.analyze(Target(url="https://example.com"))

        assert "https://example.com/api/v1/settings/global" not in calls
        assert "https://example.com/api/v1/discovery" not in calls
        assert "https://example.com/artifactory/api/system/version" not in calls
        assert "https://example.com/api/v1/settings" not in calls
        assert "https://example.com/v2/keys/?recursive=true" not in calls