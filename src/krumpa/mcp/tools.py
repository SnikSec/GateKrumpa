"""
GateKrumpa MCP tools — bridge between MCP protocol and scan engine.

Each tool is registered on a :class:`mcp.server.fastmcp.FastMCP` instance
using the ``@server.tool()`` decorator.  The resolved GateKrumpa
config is read from ``server._krumpa_config`` at call time.

Security: tool handlers receive the **already-resolved** config dict
(credentials interpolated by the provider chain), so raw secrets never
surface in MCP messages.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("krumpa.mcp.tools")


def register_default_tools(server: FastMCP, config: Optional[Dict[str, Any]] = None) -> None:
    """Register all built-in GateKrumpa tools on *server*.

    Each tool is added via ``@server.tool()`` so the official MCP SDK
    handles schema generation, validation, and transport framing.
    """
    _config = config or {}

    # Store config on server for tool access
    server._krumpa_config = _config  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Tool: scan
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_scan")
    async def gatekrumpa_scan(
        targets: list[str],
        modules: str = "",
        spec_url: str = "",
    ) -> dict[str, Any]:
        """Run a GateKrumpa security scan against one or more target URLs.

        Returns findings with severity, evidence, and remediation.

        Args:
            targets: List of target URLs to scan.
            modules: Comma-separated module names to run. Available:
                sneakygits, openkrump, bosskey, waaaghlogic,
                grotassault, redteef, waaaghgate. Omit to run all.
            spec_url: OpenAPI spec URL (passed to the openkrump module).
        """
        return await _run_scan(targets, modules, spec_url, _config)

    # ------------------------------------------------------------------
    # Tool: list_modules
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_list_modules")
    async def gatekrumpa_list_modules() -> dict[str, Any]:
        """List all available GateKrumpa scan modules with descriptions."""
        return await _list_modules_handler()

    # ------------------------------------------------------------------
    # Tool: module_info
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_module_info")
    async def gatekrumpa_module_info(module_name: str) -> dict[str, Any]:
        """Get detailed information about a specific GateKrumpa module.

        Args:
            module_name: Module name (e.g. sneakygits, bosskey, grotassault).
        """
        return await _module_info_handler(module_name)

    # ------------------------------------------------------------------
    # Tool: report
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_report")
    async def gatekrumpa_report(input_path: str, format: str) -> dict[str, Any]:
        """Convert saved GateKrumpa scan results to a different output format.

        Args:
            input_path: Path to JSON scan results file.
            format: Output format (json, sarif, markdown, html, junit).
        """
        return await _report_handler(input_path, format)

    # ------------------------------------------------------------------
    # Tool: import
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_import")
    async def gatekrumpa_import(input_path: str, format: str) -> dict[str, Any]:
        """Import targets and traffic from external tools (Burp Suite, ZAP, HAR).

        Args:
            input_path: Path to the file to import.
            format: Input format (har, burp, zap).
        """
        return await _import_handler(input_path, format)

    # ------------------------------------------------------------------
    # Tool: export
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_export")
    async def gatekrumpa_export(input_path: str) -> dict[str, Any]:
        """Export recorded GateKrumpa traffic to HAR format.

        Args:
            input_path: Path to GateKrumpa JSON scan results.
        """
        return await _export_handler(input_path)

    # ------------------------------------------------------------------
    # Tool: generate_sdk
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_generate_sdk")
    async def gatekrumpa_generate_sdk(
        spec_path: str,
        class_name: str = "ApiClient",
        base_url: str = "",
    ) -> dict[str, Any]:
        """Generate a typed Python SDK client from an OpenAPI/Swagger spec.

        Args:
            spec_path: Path or URL to the OpenAPI/Swagger spec (JSON/YAML).
            class_name: Name for the generated client class.
            base_url: Override the base URL from the spec.
        """
        return await _generate_sdk_handler(spec_path, class_name, base_url)

    # ------------------------------------------------------------------
    # Tool: cloud_scan
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_cloud_scan")
    async def gatekrumpa_cloud_scan(
        region: str = "us-east-1",
        profile: str = "",
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a CloudStrike scan against an AWS environment.

        Enumerates IAM, S3, EC2, Lambda, SageMaker, and Bedrock surfaces
        and identifies privilege escalation paths, public storage, exposed
        credentials, and AI pipeline misconfigurations.

        Args:
            region: AWS region to scan (default: us-east-1).
            profile: Named AWS profile (default: uses environment credentials).
            services: Optional list of service filters, e.g. ["s3", "iam"].
                      If omitted, all services are scanned.
        """
        return await _cloud_scan_handler(region, profile, services or [], _config)

    # ------------------------------------------------------------------
    # Tool: ai_attack
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_ai_attack")
    async def gatekrumpa_ai_attack(
        endpoint: str,
        model: str = "",
        api_key: str = "",
        attack_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run AiFuzz against an AI/LLM API endpoint.

        Tests for prompt injection, jailbreaking, token smuggling,
        system prompt extraction, guardrail bypass, indirect RAG injection,
        and sensitive data leakage in model responses.

        Args:
            endpoint: Base URL of the AI endpoint (e.g. https://api.openai.com).
            model: Model identifier (e.g. gpt-4o, claude-3-5-sonnet).
            api_key: Bearer token / API key for the endpoint.
            attack_types: Optional subset of attack types to run:
                prompt_injection, jailbreak, token_smuggling,
                system_prompt_extraction, guardrail_bypass, indirect_injection.
                Omit to run all.
        """
        return await _ai_attack_handler(endpoint, model, api_key, attack_types or [], _config)

    # ------------------------------------------------------------------
    # Tool: repo_scan
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_repo_scan")
    async def gatekrumpa_repo_scan(
        repo: str,
        provider: str = "github",
        token: str = "",
        gitlab_url: str = "",
    ) -> dict[str, Any]:
        """Run RepoScout against a GitHub or GitLab repository.

        Scans for secrets, vulnerable dependencies, insecure CI/CD pipelines,
        and exposed ML/AI pipeline configurations.

        Args:
            repo: Repository path, e.g. "org/repo".
            provider: "github" or "gitlab".
            token: Personal access token.
            gitlab_url: GitLab instance URL for self-hosted instances.
        """
        return await _repo_scan_handler(repo, provider, token, gitlab_url, _config)

    # ------------------------------------------------------------------
    # Tool: chain_attack
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_chain_attack")
    async def gatekrumpa_chain_attack(
        targets: list[str],
        modules: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a multi-surface chained scan across web, cloud, AI, and repo targets.

        Accepts mixed target schemes: https://, aws://, github://, gitlab://.
        Runs all relevant modules and correlates findings into attack chains.

        Args:
            targets: List of target URLs (mixed schemes supported).
            modules: Optional module subset. Omit to run all applicable modules.
        """
        modules_str = ",".join(modules) if modules else ""
        return await _run_scan(targets, modules_str, "", _config)

    # ------------------------------------------------------------------
    # Tool: verify
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_verify")
    async def gatekrumpa_verify(
        finding_id: str,
        scan_results_path: str,
    ) -> dict[str, Any]:
        """Re-run the stored verification path for a finding (one-click verification).

        Returns whether the finding is still exploitable ("verified"),
        has been patched ("patched"), or the result is unclear ("inconclusive").

        Args:
            finding_id: The finding ID to re-test (from scan results JSON).
            scan_results_path: Path to the saved scan results JSON file.
        """
        return await _verify_finding_handler(finding_id, scan_results_path, _config)

    # ------------------------------------------------------------------
    # Tool: push_to_tracker
    # ------------------------------------------------------------------
    @server.tool(name="gatekrumpa_push_to_tracker")
    async def gatekrumpa_push_to_tracker(
        finding_ids: list[str],
        tracker: str,
        repo_or_project: str,
        token: str,
        scan_results_path: str,
    ) -> dict[str, Any]:
        """Push verified findings to an issue tracker (agentic RBVM).

        Creates issues with full exploit path, evidence, and remediation.
        Currently supports GitHub Issues; Jira support planned.

        Args:
            finding_ids: List of finding IDs to push.
            tracker: Issue tracker to use. Currently: "github_issues".
            repo_or_project: GitHub "org/repo" or Jira project key.
            token: GitHub personal access token or Jira API token.
            scan_results_path: Path to the saved scan results JSON file.
        """
        return await _push_to_tracker_handler(
            finding_ids, tracker, repo_or_project, token, scan_results_path
        )


# ===================================================================
# Handler implementations (pure functions, no MCP dependency)
# ===================================================================

async def _run_scan(
    targets_raw: list[str],
    modules_str: str,
    spec_url: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute a scan and return the summary + findings."""
    from krumpa.core import ScanContext, Target
    from krumpa.core.auth import AuthProvider
    from krumpa.core.engine import ScanEngine

    from krumpa.__main__ import (
        _DEFAULT_ORDER,  # pyright: ignore[reportPrivateUsage]
        _load_module_class,  # pyright: ignore[reportPrivateUsage]
        _module_kwargs,  # pyright: ignore[reportPrivateUsage]
    )

    if not targets_raw:
        return {"error": "No targets specified."}

    # Module selection
    if modules_str:
        module_names = [m.strip().lower() for m in modules_str.split(",")]
    else:
        module_names = list(_DEFAULT_ORDER)

    spec: Optional[str] = spec_url or None

    # HTTP / auth from resolved config
    http_section: Dict[str, Any] = dict(config.get("http", {}))
    auth_section: Dict[str, Any] = http_section.pop("auth", {})
    if auth_section:
        http_section["auth"] = AuthProvider(**auth_section)

    ctx = ScanContext(config=config)
    for url in targets_raw:
        ctx.add_target(Target(url=url))

    engine = ScanEngine(ctx=ctx, http_config=http_section)
    for name in module_names:
        cls = _load_module_class(name)
        kwargs = _module_kwargs(name, config, spec=spec)
        engine.register(cls(**kwargs))

    result_ctx = await engine.run_all()
    summary = result_ctx.summary()
    findings = [f.to_dict() for f in result_ctx.findings]

    return {
        "scan_id": summary["scan_id"],
        "total_targets": summary["total_targets"],
        "total_findings": summary["total_findings"],
        "findings_by_severity": summary["findings_by_severity"],
        "findings": findings,
    }


async def _list_modules_handler() -> Dict[str, Any]:
    from krumpa.__main__ import _DEFAULT_ORDER, _load_module_class  # pyright: ignore[reportPrivateUsage]

    modules: List[Dict[str, str]] = []
    for name in _DEFAULT_ORDER:
        cls = _load_module_class(name)
        inst = cls.__new__(cls)
        modules.append({
            "name": name,
            "class": cls.__qualname__,
            "description": getattr(inst, "description", ""),
        })
    return {"modules": modules}


async def _module_info_handler(module_name: str) -> Dict[str, Any]:
    from krumpa.__main__ import _load_module_class  # pyright: ignore[reportPrivateUsage]

    name = module_name.strip().lower()
    if not name:
        return {"error": "module_name is required."}

    try:
        cls = _load_module_class(name)
    except Exception as exc:
        return {"error": str(exc)}

    inst = cls.__new__(cls)
    return {
        "name": getattr(inst, "name", name),
        "class": cls.__qualname__,
        "description": getattr(inst, "description", "N/A"),
        "dependencies": getattr(inst, "dependencies", []),
    }


async def _report_handler(input_path: str, fmt: str) -> Dict[str, Any]:
    from krumpa.core import Finding, ScanContext, Severity, Target
    from krumpa.core.reporting import (
        to_html,
        to_json,
        to_junit,
        to_markdown,
        to_sarif,
    )

    if not input_path:
        return {"error": "input_path is required."}

    fmt = fmt.lower()
    p = Path(input_path)
    if not p.exists():
        return {"error": f"Input file not found: {input_path}"}

    data = json.loads(p.read_text(encoding="utf-8"))
    ctx = ScanContext(scan_id=data.get("scan_id", "unknown"))

    for fd in data.get("findings", []):
        target = Target(url=fd["target"]) if fd.get("target") else None
        ctx.add_finding(Finding(
            id=fd.get("id", ""),
            title=fd.get("title", ""),
            description=fd.get("description", ""),
            severity=Severity(fd.get("severity", "info")),
            module=fd.get("module", ""),
            target=target,
            evidence=fd.get("evidence", ""),
            remediation=fd.get("remediation", ""),
            cwe=fd.get("cwe"),
            cvss_score=fd.get("cvss_score"),
            tags=fd.get("tags", []),
        ))

    formatters = {
        "json": to_json,
        "sarif": lambda c: json.dumps(to_sarif(c), indent=2),
        "markdown": to_markdown,
        "html": to_html,
        "junit": to_junit,
    }

    fn = formatters.get(fmt)
    if not fn:
        return {"error": f"Unknown format: {fmt}. Use: json, sarif, markdown, html, junit"}

    content = fn(ctx)
    return {"format": fmt, "content": content}


async def _import_handler(input_path: str, fmt: str) -> Dict[str, Any]:
    from krumpa.core.exchange import import_burp_xml, import_har, import_zap_json

    if not input_path:
        return {"error": "input_path is required."}
    if not fmt:
        return {"error": "format is required (har, burp, zap)."}

    fmt = fmt.lower()
    p = Path(input_path)
    if not p.exists():
        return {"error": f"Input file not found: {input_path}"}

    raw = p.read_text(encoding="utf-8")

    if fmt == "har":
        data = json.loads(raw)
        targets, records = import_har(data)
    elif fmt == "burp":
        targets, records = import_burp_xml(raw)
    elif fmt == "zap":
        data = json.loads(raw)
        targets, records = import_zap_json(data)
    else:
        return {"error": f"Unknown format: {fmt}. Use: har, burp, zap"}

    return {
        "imported_targets": len(targets),
        "imported_records": len(records),
        "targets": [{"url": t.url, "method": t.method} for t in targets],
    }


async def _export_handler(input_path: str) -> Dict[str, Any]:
    from krumpa.core.exchange import export_har
    from krumpa.core.recorder import RequestRecord

    if not input_path:
        return {"error": "input_path is required."}

    p = Path(input_path)
    if not p.exists():
        return {"error": f"Input file not found: {input_path}"}

    data = json.loads(p.read_text(encoding="utf-8"))

    records: List[RequestRecord] = []
    for rd in data.get("records", []):
        records.append(RequestRecord(
            method=rd.get("method", "GET"),
            url=rd.get("url", ""),
            status_code=rd.get("status_code", 0),
            request_headers=rd.get("request_headers", {}),
            response_headers=rd.get("response_headers", {}),
            duration_ms=rd.get("duration_ms", 0),
            request_body=rd.get("request_body"),
            response_body_preview=rd.get("response_body_preview", ""),
        ))

    har = export_har(records)
    return {
        "format": "har",
        "records_exported": len(records),
        "content": json.dumps(har, indent=2),
    }


async def _generate_sdk_handler(
    spec_path: str,
    class_name: str,
    base_url: str,
) -> Dict[str, Any]:
    from krumpa.openkrump.parser import SpecParser
    from krumpa.openkrump.sdk_generator import generate_sdk

    if not spec_path:
        return {"error": "spec_path is required."}

    from krumpa.__main__ import _load_spec  # pyright: ignore[reportPrivateUsage]
    try:
        spec_data = _load_spec(spec_path)
    except Exception as exc:
        return {"error": f"Failed to load spec: {exc}"}

    parser = SpecParser(base_url=base_url or None)
    endpoints = parser.parse(spec_data)

    if not endpoints:
        return {"error": "No endpoints found in the spec."}

    resolved_base = base_url or parser.resolve_url(spec_data, "")
    code = generate_sdk(
        spec_data,
        endpoints,
        resolved_base,
        class_name=class_name,
    )

    return {
        "class_name": class_name,
        "endpoint_count": len(endpoints),
        "code": code,
    }


async def _cloud_scan_handler(
    region: str,
    profile: str,
    services: List[str],
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Run CloudStrike against an AWS target and return findings."""
    from krumpa.core import ScanContext, Target
    from krumpa.core.engine import ScanEngine

    target_url = f"aws://{region}"
    metadata: Dict[str, Any] = {"aws_region": region}
    if profile:
        metadata["aws_profile"] = profile

    ctx = ScanContext(config=config)
    ctx.add_target(Target(url=target_url, metadata=metadata))

    try:
        from krumpa.cloudstrike.module import CloudStrikeModule
    except ImportError:
        return {"error": "boto3 not installed. Install with: pip install gatekrumpa[cloud]"}

    engine = ScanEngine(ctx=ctx)
    engine.register(CloudStrikeModule())
    result_ctx = await engine.run_all()

    findings = [f.to_dict() for f in result_ctx.findings]
    return {"summary": result_ctx.summary(), "findings": findings}


async def _ai_attack_handler(
    endpoint: str,
    model: str,
    api_key: str,
    attack_types: List[str],
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Run AiFuzz against an AI endpoint and return findings."""
    from krumpa.core import ScanContext, Target
    from krumpa.core.engine import ScanEngine

    metadata: Dict[str, Any] = {}
    if model:
        metadata["ai_model"] = model
    if api_key:
        metadata["ai_api_key"] = api_key

    ctx = ScanContext(config=config)
    ctx.add_target(Target(url=endpoint, metadata=metadata))

    from krumpa.aifuzz.module import AiFuzzModule

    # Temporarily mark the target as having AI tech signals so aifuzz picks it up
    from krumpa.sneakygits.fingerprint import FingerprintResult
    ctx.metadata.setdefault("fingerprints", {})[endpoint] = FingerprintResult(
        url=endpoint,
        technologies=["OpenAI-compatible API"],
    )

    engine = ScanEngine(ctx=ctx)
    engine.register(AiFuzzModule())
    result_ctx = await engine.run_all()

    findings = [f.to_dict() for f in result_ctx.findings]
    return {"summary": result_ctx.summary(), "findings": findings}


async def _repo_scan_handler(
    repo: str,
    provider: str,
    token: str,
    gitlab_url: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Run RepoScout against a GitHub/GitLab repository and return findings."""
    from krumpa.core import ScanContext, Target
    from krumpa.core.engine import ScanEngine

    scheme = "github" if provider.lower() == "github" else "gitlab"
    if scheme == "gitlab" and gitlab_url:
        parsed_host = gitlab_url.rstrip("/").replace("https://", "").replace("http://", "")
        target_url = f"gitlab://{parsed_host}/{repo}"
    else:
        target_url = f"{scheme}://{repo}"

    metadata: Dict[str, Any] = {}
    if token:
        metadata["repo_token"] = token

    ctx = ScanContext(config=config)
    ctx.add_target(Target(url=target_url, metadata=metadata))

    try:
        from krumpa.reposcout.module import RepoScoutModule
    except ImportError:
        return {"error": "PyGithub/python-gitlab not installed. Install with: pip install gatekrumpa[repo]"}

    engine = ScanEngine(ctx=ctx)
    engine.register(RepoScoutModule())
    result_ctx = await engine.run_all()

    findings = [f.to_dict() for f in result_ctx.findings]
    return {"summary": result_ctx.summary(), "findings": findings}


async def _verify_finding_handler(
    finding_id: str,
    scan_results_path: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Re-run the stored verification path for a finding."""
    from krumpa.core import ScanContext
    from krumpa.core.http_client import HttpClient
    from krumpa.waaaghgate.verification_runner import VerificationRunner
    import json
    from pathlib import Path

    p = Path(scan_results_path)
    if not p.exists():
        return {"error": f"Scan results file not found: {scan_results_path}"}

    data = json.loads(p.read_text())
    ctx = ScanContext(scan_id=data.get("scan_id", "unknown"))
    ctx.metadata["verification_paths"] = data.get("verification_paths", {})

    if finding_id not in ctx.metadata["verification_paths"]:
        return {
            "finding_id": finding_id,
            "status": "inconclusive",
            "evidence": "No verification path found for this finding ID.",
        }

    http_client = HttpClient(timeout=30.0, retries=1)
    ctx.http_client = http_client
    try:
        result = await VerificationRunner().verify(finding_id, ctx)
    finally:
        await http_client.close()

    return result.to_dict()


async def _push_to_tracker_handler(
    finding_ids: List[str],
    tracker: str,
    repo_or_project: str,
    token: str,
    scan_results_path: str,
) -> Dict[str, Any]:
    """Create GitHub issues for verified findings."""
    import json
    from pathlib import Path

    p = Path(scan_results_path)
    if not p.exists():
        return {"error": f"Scan results file not found: {scan_results_path}"}

    data = json.loads(p.read_text())
    findings_by_id = {f.get("id"): f for f in data.get("findings", [])}
    created: List[str] = []
    errors: List[str] = []

    for fid in finding_ids:
        finding = findings_by_id.get(fid)
        if not finding:
            errors.append(f"Finding {fid!r} not found in scan results")
            continue

        title = f"[GateKrumpa] {finding.get('title', 'Security Finding')}"
        body = (
            f"**Severity:** {finding.get('severity', 'unknown').upper()}\n\n"
            f"**Description:** {finding.get('description', '')}\n\n"
            f"**Evidence:**\n```\n{finding.get('evidence', '')}\n```\n\n"
            f"**Remediation:** {finding.get('remediation', '')}\n\n"
            f"**Finding ID:** `{fid}`\n"
            f"**Tags:** {', '.join(finding.get('tags', []))}\n"
        )

        if tracker == "github_issues":
            url = await _create_github_issue(repo_or_project, token, title, body)
            if url:
                created.append(url)
            else:
                errors.append(f"Failed to create GitHub issue for {fid}")
        else:
            errors.append(f"Tracker {tracker!r} not yet supported")

    return {"created": created, "errors": errors, "total_created": len(created)}


async def _create_github_issue(
    repo: str, token: str, title: str, body: str
) -> Optional[str]:
    """Create a GitHub issue; return its HTML URL or None on failure."""
    import json
    from krumpa.core.http_client import HttpClient

    client = HttpClient(timeout=15.0, retries=1)
    try:
        resp = await client.request(
            "POST",
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
            content=json.dumps({"title": title, "body": body}),
        )
        text = getattr(resp, "text", "") or ""
        return json.loads(text).get("html_url")
    except Exception:
        return None
    finally:
        await client.close()
