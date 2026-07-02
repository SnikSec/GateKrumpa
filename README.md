# GateKrumpa

A modular dynamic attack simulation platform for external APIs, cloud environments, AI/LLM systems, and source repositories.

**Version:** 0.2.0 · **Codename:** GateKrumpa · **1118 tests passing**

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [CLI Commands](#cli-commands)
- [Core Package](#core-package)
- [Modules](#modules)
  - [1. SneakyGits — Recon](#1-sneakygits--recon)
  - [2. BossKey — Auth Modeling](#2-bosskey--auth-modeling)
  - [3. WaaaghLogic — Business Logic Testing](#3-waaaghlogic--business-logic-testing)
  - [4. GrotAssault — Mutation Fuzzing](#4-grotassault--mutation-fuzzing)
  - [5. RedTeef — Exploit Confirmation](#5-redteef--exploit-confirmation)
  - [6. WaaaghGate — CI/CD Integration](#6-waaaghgate--cicd-integration)
  - [7. OpenKrump — API-First Design](#7-openkrump--api-first-design)
  - [8. CloudStrike — AWS Attack Surface](#8-cloudstrike--aws-attack-surface)
  - [9. AiFuzz — AI/LLM Attack Surface](#9-aifuzz--aillm-attack-surface)
  - [10. ModelHunt — Model Analysis](#10-modelhunt--model-analysis)
  - [11. RepoScout — Repository Targeting](#11-reposcout--repository-targeting)
- [MCP Server](#mcp-server)
- [Credential Management](#credential-management)
- [Import / Export](#import--export)
- [SDK Generation](#sdk-generation)
- [Configuration](#configuration)
- [Running Tests](#running-tests)

---

## Quick Start

```bash
pip install -e ".[dev,yaml,mcp]"
# or
python3.11 -m pip install -r requirements.txt

# Web application scan
gatekrumpa scan -t https://target.example.com -f json -o ./output/

# AWS environment scan (requires [cloud] extra)
pip install -e ".[cloud]"
gatekrumpa scan --target aws://us-east-1 --modules cloudstrike --aws-profile myprofile

# AI/LLM endpoint attack
gatekrumpa scan --target https://api.openai.com --modules aifuzz --ai-key $OPENAI_KEY --ai-model gpt-4o

# Repository scan (requires [repo] extra)
pip install -e ".[repo]"
gatekrumpa scan --target github://org/repo --modules reposcout --repo-token $GH_TOKEN

# Re-verify a patched finding (one-click verification)
gatekrumpa verify --finding-id abc123 --input ./output/scan.json

# List modules
gatekrumpa modules list

# Start MCP server for AI agent integration
gatekrumpa mcp-serve --config configs/default.yaml
```

---

## Architecture

```
src/krumpa/
├── core/              # Shared engine, HTTP client, data models, reporting,
│                      #   credentials, exchange, events, recording, scope,
│                      #   attack_chain, hvt_scorer, ai_orchestrator
├── mcp/               # MCP server (official SDK) — 11 tools for AI agents
├── sneakygits/        # Module 1  — Recon, fingerprinting, passive recon
├── bosskey/           # Module 2  — Auth, session, cloud identity
├── waaaghlogic/       # Module 3  — Business logic testing
├── grotassault/       # Module 4  — Mutation fuzzing (46 SSRF payloads)
├── redteef/           # Module 5  — Exploit confirmation
├── waaaghgate/        # Module 6  — CI/CD gate, blast radius, verification
├── openkrump/         # Module 7  — API-first (OpenAPI/Swagger/gRPC)
├── cloudstrike/       # Module 8  — AWS attack surface (aws:// targets)
├── aifuzz/            # Module 9  — AI/LLM attack surface
├── modelhunt/         # Module 10 — Model extraction, vector DB, supply chain
└── reposcout/         # Module 11 — GitHub/GitLab targeting (github:// targets)
```

Each module follows a consistent pattern: domain-specific helper classes plus a `module.py` containing a `BaseModule` subclass that orchestrates the helpers within a `ScanContext`.

**Pipeline order:**
`sneakygits → openkrump → cloudstrike → reposcout → bosskey → waaaghlogic → aifuzz → grotassault → redteef → modelhunt → waaaghgate`

**Target URL schemes** — non-HTTP targets use pseudo-URL schemes that plug into the existing `Target` model:

| Scheme | Example | Module |
|--------|---------|--------|
| `https://` | `https://api.openai.com/v1/chat/completions` | `aifuzz`, `modelhunt` |
| `aws://` | `aws://us-east-1` | `cloudstrike` |
| `github://` | `github://org/repo` | `reposcout` |
| `gitlab://` | `gitlab://gitlab.example.com/group/repo` | `reposcout` |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `gatekrumpa scan` | Run a security scan against one or more targets |
| `gatekrumpa verify` | Re-run a stored verification path (one-click verification) |
| `gatekrumpa modules list` | List all available modules |
| `gatekrumpa modules info <name>` | Show details about a specific module |
| `gatekrumpa report` | Convert saved scan results to a different format |
| `gatekrumpa import` | Import targets from HAR, Burp XML, or ZAP JSON files |
| `gatekrumpa export` | Export recorded traffic to HAR format |
| `gatekrumpa generate-sdk` | Generate a typed Python SDK client from an OpenAPI spec |
| `gatekrumpa mcp-serve` | Start the MCP server (stdio transport) for AI agents |

### Scan flags

```
-t, --target URL          Target URL (repeatable). Use aws://REGION for cloud,
                          github://ORG/REPO for repositories.
--targets-file PATH       File with one URL per line
-m, --modules LIST        Comma-separated module names (default: all)
-c, --config PATH         YAML/JSON config file
--spec URL                OpenAPI spec URL (passed to openkrump)
-f, --format LIST         Output formats: json, sarif, markdown, html, junit
-o, --output DIR          Output directory (default: stdout)
-v / -vv                  Increase verbosity (info / debug)
--aws-profile NAME        AWS named profile for cloudstrike
--aws-region REGION       AWS region (default: us-east-1)
--repo-token TOKEN        GitHub/GitLab personal access token for reposcout
--ai-key KEY              API key for AI/LLM endpoint (aifuzz/modelhunt)
--ai-model MODEL          Model identifier (e.g. gpt-4o, claude-3-5-sonnet)
```

### Verify flags

```
-f, --finding-id ID       Finding ID to re-test
-i, --input PATH          Path to the JSON scan results file
```

---

## Core Package

`krumpa.core` provides the shared foundation used by every module.

### Data Models (`core/__init__.py`)

| Export | Type | Description |
|--------|------|-------------|
| `Severity` | Enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `TargetType` | Enum | `WEB`, `AWS`, `GITHUB`, `GITLAB` — inferred from URL scheme |
| `ModuleStatus` | Enum | `PENDING`, `RUNNING`, `COMPLETED`, `FAILED` |
| `Target` | Dataclass | Scan target with `url`, `method`, `headers`, `body`, `meta`, `target_type` |
| `Finding` | Dataclass | Vulnerability finding with `title`, `severity`, `description`, `evidence`, `tags`; method: `to_dict()` |
| `ScanContext` | Dataclass | Shared mutable state holding targets and findings; methods: `add_finding()`, `add_target()`, `summary()` |
| `BaseModule` | ABC | Abstract base for all modules; abstract `run(context)`, plus `setup()`, `teardown()`, `add_finding()`, `reset()` |

### Scan Engine (`core/engine.py`)

| Export | Type | Description |
|--------|------|-------------|
| `ScanEngine` | Class | Registers and runs modules via Kahn topological sort with `asyncio.gather` parallelism |

### Attack Chain Engine (`core/attack_chain.py`)

| Export | Type | Description |
|--------|------|-------------|
| `AttackChain` | Dataclass | Multi-step attack path: `steps`, `confidence`, `blast_radius`, `title` |
| `AttackChainBuilder` | Class | Correlates findings into chains (8 patterns); stores in `ctx.metadata["attack_chains"]` |

### High-Value Target Scorer (`core/hvt_scorer.py`)

| Export | Type | Description |
|--------|------|-------------|
| `HVTScorer` | Class | Two-phase target prioritisation (pattern matching + optional AutoGen LLM reranking) |
| `TargetScore` | Dataclass | `score`, `priority`, `signals` per target |

### AI Orchestrator (`core/ai_orchestrator.py`)

| Export | Type | Description |
|--------|------|-------------|
| `TryHarderAgent` | Class | AutoGen agent: suggests alternative techniques at dead-ends. Optional `[ai]` extra. |
| `AttackPlannerAgent` | Class | AutoGen agent: plans next scan phase and reranks HVT scores. Optional `[ai]` extra. |

### HTTP Client (`core/http_client.py`)

| Export | Type | Description |
|--------|------|-------------|
| `HttpClient` | Class | `httpx`-backed async client with retry, rate-limiting, proxy support, SSRF protection, mTLS |

### Reporting (`core/reporting.py`)

| Function | Format | Description |
|----------|--------|-------------|
| `to_json()` | JSON | Full scan serialization, findings sorted by severity |
| `to_sarif()` | SARIF v2.1.0 | CI/CD-ready SARIF output |
| `to_markdown()` | Markdown | Human-readable report with severity badges |
| `to_html()` | HTML | Self-contained styled report with summary cards and table |
| `to_junit()` | JUnit XML | Findings as `<testcase>` elements grouped by module |

### Additional Core Components

| File | Description |
|------|-------------|
| `credentials.py` | Credential provider chain — env vars, HashiCorp Vault, Azure Key Vault, AWS Secrets Manager |
| `exchange.py` | Import/export converters — HAR 1.2, Burp XML, ZAP JSON |
| `events.py` | EventBus — publish-subscribe with sync/async listeners |
| `recorder.py` | Request recording for traffic capture |
| `scope.py` | Scope management and target filtering |
| `auth.py` | Auth middleware (bearer, API key, basic) |
| `scan_persistence.py` | Checkpoint/resume for long-running scans |
| `scan_isolation.py` | Concurrent scan isolation |

---

## Modules

### 1. SneakyGits — Recon

> Target enumeration, crawling, fingerprinting, and passive recon.

**Capabilities:** Crawling, content/directory discovery, JS endpoint/secret extraction (incl. AWS/GCP/GitHub key patterns), source map detection, SSL/TLS analysis, backup file scanning, WAF/CDN detection, HTTP method discovery, information leakage scanning, fingerprint DB (200+ signatures including cloud LBs and AI infra), DNS enumeration, platform exposure (Kubernetes, Docker, Harbor, Argo CD, Jenkins, Grafana, Prometheus, MLflow, Triton, Ollama, and more), passive recon (Wayback Machine, Common Crawl, parameter mining, subdomain takeover detection), directory listing detection (DAST-H1), JS body parameter harvesting (DAST-H2).

| File | Export | Type | Description |
|------|--------|------|-------------|
| `crawler.py` | `Crawler` | Class | Async web crawler; discovers endpoints via HTML links, robots.txt, sitemaps, JS extraction |
| `fingerprint.py` | `Fingerprinter` | Class | Returns `FingerprintResult` with technologies, raw headers, body excerpt, cookies, redirect chain |
| `platform_exposure.py` | `PlatformExposureAnalyzer` | Class | Safely detects exposed Kubernetes, container, admin, and AI/ML surfaces |
| `passive_recon.py` | `PassiveReconAnalyzer` | Class | Wayback/CommonCrawl URL harvesting, parameter mining, subdomain takeover detection |
| `js_extractor.py` | `JsExtractor` | Class | JS endpoint/secret extraction; body param harvesting; directory listing detection |
| `module.py` | `SneakyGitsModule` | BaseModule | Orchestrates full recon pipeline |

---

### 2. BossKey — Auth Modeling

> Authentication modeling, session analysis, credential testing, and cloud identity.

**Capabilities:** All original auth capabilities plus AWS Cognito user pool analysis (user enumeration, hosted UI open redirect), Azure Entra ID multi-tenant misconfiguration detection, Google IAP JWT validation gaps, PKCE enforcement testing, implicit flow detection, broad scope detection.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `session_analyzer.py` | `SessionAnalyzer` | Class | Cookie and JWT analysis (entropy, flags, algorithm, expiry) |
| `auth_probe.py` | `AuthProbe` | Class | Default credential probing |
| `jwt_attacks.py` | `JwtAttacker` | Class | JWT key confusion, JWK/jku injection, kid attacks |
| `oauth2_analyzer.py` | `OAuth2Analyzer` | Class | OAuth2 flow analysis |
| `cloud_identity.py` | `CloudIdentityAnalyzer` | Class | Cognito, Entra ID, GCP IAP, PKCE enforcement |
| `module.py` | `BossKeyModule` | BaseModule | Orchestrates auth testing pipeline |

---

### 3. WaaaghLogic — Business Logic Testing

> Business logic vulnerability detection.

**Capabilities:** Mass assignment, privilege escalation, file upload abuse, pagination abuse, idempotency/TOCTOU, flow analysis, data validation bypass, numeric precision, input length boundary, bulk operation abuse, state machine modeling, GraphQL logic, workflow integrity, currency rounding, rate-limit bypass.

---

### 4. GrotAssault — Mutation Fuzzing

> Mutation-based fuzz testing. **46 SSRF payloads** including in-cluster Kubernetes services and ML/AI internal endpoints.

**Capabilities:** All original fuzzing capabilities plus in-cluster K8s service SSRF targets (`kubernetes.default.svc`, `etcd.kube-system`), ML/AI internal service targets (MLflow, Kubeflow, Triton), service-account token path indicators.

---

### 5. RedTeef — Exploit Confirmation

> Exploit validation and false-positive reduction with one-click verification path storage.

**Capabilities:** All original confirmation capabilities. Confirmed findings store a `VerificationPath` in `finding.raw["verification_path"]` for use with `gatekrumpa verify`.

---

### 6. WaaaghGate — CI/CD Integration

> Quality-gate evaluation, multi-format reporting, blast radius analysis, and one-click verification.

**Capabilities:** All original gate capabilities plus attack chain correlation (step 12), HVT scoring (step 13), blast radius severity adjustment (step 14), Sankey diagram data generation for HTML report. One-click verification via `VerificationRunner`.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `gate.py` | `GatePolicy` | Class | Severity-based quality gate |
| `reporter.py` | `PipelineReporter` | Class | Multi-format report generation |
| `blast_radius.py` | `BlastRadiusAnalyzer` | Class | Contextual severity override based on attack chains and HVT priority |
| `verification_runner.py` | `VerificationRunner` | Class | Stores and replays exact exploit paths for patch verification |
| `module.py` | `WaaaghGateModule` | BaseModule | Orchestrates gate, reporting, chain correlation, HVT scoring |

---

### 7. OpenKrump — API-First Design

> API spec parsing, validation, and target generation.

**Capabilities:** Swagger 2.0, OpenAPI 3.x, GraphQL schema analysis, mass assignment from spec, response schema validation, excessive data exposure, BOLA generator, spec diff/shadow API detection, gRPC/Protobuf support, example-based testing, API versioning detection, webhook security.

---

### 8. CloudStrike — AWS Attack Surface

> AWS environment attack surface analysis. Handles `aws://REGION` targets. Requires `pip install gatekrumpa[cloud]`.

**Capabilities:** Asset enumeration (S3, EC2, IAM, Lambda, ECR, EKS, SageMaker, Bedrock), IAM privilege escalation path analysis (PassRole, CreatePolicyVersion, AssumeRole chains), S3 public access/ACL/CORS/encryption/replication auditing, IMDS exposure with SSRF chain correlation, credential harvesting (EC2 userdata, Lambda env, ECS, SSM), data exfiltration surface (replication rules, pre-signed URL permissions), AI pipeline scanning (SageMaker notebook internet access, training data exposure, Bedrock logging).

```bash
gatekrumpa scan --target aws://us-east-1 --modules cloudstrike --aws-profile myprofile
```

| File | Export | Type | Description |
|------|--------|------|-------------|
| `aws_recon.py` | `AwsRecon` | Class | Enumerate AWS assets; stores inventory in `ctx.metadata["aws_inventory"]` |
| `iam_pathfinder.py` | `IamPathfinder` | Class | Build IAM permission graph; detect privilege escalation paths |
| `s3_auditor.py` | `S3Auditor` | Class | Per-bucket security audit (public access, CORS, encryption, replication) |
| `metadata_service.py` | `MetadataServiceAnalyzer` | Class | IMDSv1/v2 exposure + SSRF chain correlation |
| `credential_harvester.py` | `CredentialHarvester` | Class | Credential patterns in EC2 userdata, Lambda env, ECS, SSM |
| `data_exfiltration.py` | `DataExfiltrationAnalyzer` | Class | S3 replication abuse, pre-signed URL permission surface |
| `ai_pipeline_scanner.py` | `AiPipelineScanner` | Class | SageMaker/Bedrock AI pipeline security |
| `module.py` | `CloudStrikeModule` | BaseModule | Orchestrates AWS attack surface analysis |

---

### 9. AiFuzz — AI/LLM Attack Surface

> AI/LLM endpoint attack surface testing. Targets standard HTTPS endpoints and fingerprint-identified AI services.

**Capabilities:** Direct prompt injection (6 canary payloads), jailbreaking (DAN, roleplay, developer mode, nested context, token budget), token smuggling/tokenizer exploits (8 mutation strategies — base64, homoglyphs, zero-width, fragmentation, ROT13, leetspeak, reversed, hex-escape), system prompt extraction (7 techniques), guardrail bypass via differential analysis, indirect RAG injection (HTML, markdown, JSON-LD, YAML), LLM response scanning for PII/credentials/system prompt fragments.

```bash
gatekrumpa scan --target https://api.openai.com --modules aifuzz --ai-key $OPENAI_KEY --ai-model gpt-4o
```

| File | Export | Type | Description |
|------|--------|------|-------------|
| `prompt_injector.py` | `PromptInjector` | Class | Direct prompt injection with canary indicators |
| `jailbreak_tester.py` | `JailbreakTester` | Class | Jailbreak via roleplay, DAN, developer mode, nested context |
| `token_smuggler.py` | `TokenSmuggler` | Class | 8 tokenizer exploit mutation strategies |
| `system_prompt_extractor.py` | `SystemPromptExtractor` | Class | 7 system prompt leakage techniques |
| `guardrail_bypass.py` | `GuardrailBypass` | Class | Differential analysis of guardrail blind spots |
| `indirect_injector.py` | `IndirectInjector` | Class | RAG-targeted adversarial document payloads |
| `response_analyzer.py` | `ResponseAnalyzer` | Class | PII, credential, and system prompt leakage detection |
| `module.py` | `AiFuzzModule` | BaseModule | Orchestrates AI/LLM attack surface testing |

---

### 10. ModelHunt — Model Analysis

> AI model extraction, membership inference, and supply chain auditing. Depends on `aifuzz`.

**Capabilities:** Behavioral fingerprinting via systematic API probing, training data memorisation detection (verbatim vs. paraphrase completion differential), targeted PII/credential extraction prompts, exposed vector database scanning (Qdrant, Weaviate, Chroma, Milvus — unauthenticated collection enumeration), HuggingFace model card analysis (pickle vs. safetensors), PyPI typosquatting detection for 10 AI packages, OSV.dev CVE lookup.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `model_extractor.py` | `ModelExtractor` | Class | Behavioral fingerprinting and model identity detection |
| `membership_inference.py` | `MembershipInferenceProber` | Class | Training data memorisation via completion differential |
| `pii_extractor.py` | `PiiExtractor` | Class | Targeted PII/credential extraction prompts |
| `vector_db_scanner.py` | `VectorDbScanner` | Class | Unauthenticated vector DB endpoint detection |
| `supply_chain_auditor.py` | `SupplyChainAuditor` | Class | HuggingFace/PyPI supply chain risk analysis |
| `module.py` | `ModelHuntModule` | BaseModule | Orchestrates model analysis pipeline |

---

### 11. RepoScout — Repository Targeting

> Repository targeting for secrets, supply chain, and CI/CD analysis. Handles `github://` and `gitlab://` targets. Requires `pip install gatekrumpa[repo]`.

**Capabilities:** GitHub REST+GraphQL and GitLab REST enumeration (file tree, CI configs, commits), secret scanning (13 patterns — AWS keys, GitHub/OpenAI/Anthropic tokens, DB URLs, private keys, HuggingFace tokens; evidence always redacted), dependency auditing (requirements.txt, package.json, Cargo.toml, go.mod, Gemfile; OSV.dev batch API), CI/CD pipeline analysis (GitHub Actions: hardcoded secrets, write-all permissions, unpinned actions, pwn-request risk, AWS creds without OIDC; GitLab CI equivalent), MLOps scanning (MLflow URLs, W&B API keys, DVC paths, S3 training URIs, Dockerfile model weights, HuggingFace model ID discovery).

```bash
gatekrumpa scan --target github://org/repo --modules reposcout --repo-token $GH_TOKEN
```

| File | Export | Type | Description |
|------|--------|------|-------------|
| `repo_crawler.py` | `RepoCrawler` | Class | GitHub REST+GraphQL and GitLab REST repository enumeration |
| `secret_scanner.py` | `SecretScanner` | Class | 13-pattern credential scanner; evidence always redacted |
| `dependency_auditor.py` | `DependencyAuditor` | Class | Multi-format manifest parsing + OSV.dev CVE lookup |
| `pipeline_analyzer.py` | `PipelineAnalyzer` | Class | GitHub Actions and GitLab CI security analysis |
| `mlops_scanner.py` | `MlopsScanner` | Class | MLOps pipeline configuration exposure scanning |
| `module.py` | `RepoScoutModule` | BaseModule | Orchestrates repository targeting pipeline |

---

## MCP Server

GateKrumpa includes a Model Context Protocol (MCP) server built on the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (`FastMCP`). This allows AI agents (Claude, Copilot, etc.) to invoke scan tools directly.

```bash
pip install -e ".[mcp]"
gatekrumpa mcp-serve --config configs/default.yaml
```

### MCP client configuration

```json
{
  "mcpServers": {
    "gatekrumpa": {
      "command": "gatekrumpa",
      "args": ["mcp-serve", "--config", "configs/default.yaml"]
    }
  }
}
```

### Available tools

| Tool | Description |
|------|-------------|
| `gatekrumpa_scan` | Run a web/API security scan against target URLs |
| `gatekrumpa_cloud_scan` | Scan an AWS environment (region, profile, service filters) |
| `gatekrumpa_ai_attack` | Attack an AI/LLM endpoint (model, key, attack type selection) |
| `gatekrumpa_repo_scan` | Scan a GitHub/GitLab repository (token, provider) |
| `gatekrumpa_chain_attack` | Multi-surface chained scan across mixed target schemes |
| `gatekrumpa_verify` | Re-run a stored verification path (one-click verification) |
| `gatekrumpa_push_to_tracker` | Push verified findings to GitHub Issues (agentic RBVM) |
| `gatekrumpa_list_modules` | List all available scan modules |
| `gatekrumpa_module_info` | Get detailed info about a specific module |
| `gatekrumpa_report` | Convert scan results to json/sarif/markdown/html/junit |
| `gatekrumpa_import` | Import targets from HAR/Burp/ZAP files |
| `gatekrumpa_export` | Export recorded traffic to HAR format |
| `gatekrumpa_generate_sdk` | Generate a typed Python SDK from an OpenAPI spec |

Credential references (`${VAR}`, `vault://`) are resolved before tool handlers run; agents never see raw secrets.

---

## Credential Management

GateKrumpa resolves secrets via a provider chain — no plaintext credentials in config files.

### Provider chain (priority order)

1. **Environment variables** — `${VAR}` or `${VAR:-default}` syntax, optional prefix
2. **HashiCorp Vault** — `vault://secret/data/path#field`
3. **Azure Key Vault** — `vault://secret-name`
4. **AWS Secrets Manager** — `vault://secret-name#field`

### Configuration

```yaml
credentials:
  env_prefix: "GK_"
  vault:
    type: hashicorp
    addr: "https://vault.example.com"

http:
  auth:
    auth_type: bearer
    token: "${API_TOKEN}"
```

---

## Import / Export

| Format | Command |
|--------|---------|
| HAR 1.2 (import) | `gatekrumpa import -i traffic.har -f har` |
| Burp XML (import) | `gatekrumpa import -i history.xml -f burp` |
| ZAP JSON (import) | `gatekrumpa import -i messages.json -f zap` |
| HAR 1.2 (export) | `gatekrumpa export -i scan.json -f har` |

---

## SDK Generation

```bash
gatekrumpa generate-sdk --spec ./openapi.json -o client.py --class-name MyApiClient
gatekrumpa generate-sdk --spec https://api.example.com/openapi.json -o client.py
```

---

## Configuration

```yaml
scan:
  modules: [sneakygits, openkrump, cloudstrike, reposcout, bosskey,
            waaaghlogic, aifuzz, grotassault, redteef, modelhunt, waaaghgate]
  formats: [json, markdown]

http:
  timeout: 30.0
  retries: 3
  verify_ssl: true
  rate_limit: 0.0

sneakygits:
  max_depth: 3
  max_pages: 500

waaaghgate:
  policy:
    fail: { critical: 1, high: 5 }
    warn: { medium: 10 }
    ignore_tags: [accepted-risk]
```

---

## Running Tests

```bash
# All 1118 tests
pytest

# Verbose with short tracebacks
pytest -v --tb=short

# By module
pytest tests/test_sneakygits/
pytest tests/test_cloudstrike/
pytest tests/test_aifuzz/
pytest tests/test_modelhunt/
pytest tests/test_reposcout/
pytest tests/test_core/
pytest tests/test_mcp/

# Type checking (0 errors, 0 warnings)
pyright src/
```

### Test matrix

| Test directory | Coverage |
|----------------|----------|
| `test_sneakygits/` | Crawling, fingerprinting, passive recon, header audit, CORS, platform exposure |
| `test_bosskey/` | Session analysis, JWT, auth probing, CSRF, cloud identity |
| `test_waaaghlogic/` | Flow analysis, idempotency, TOCTOU |
| `test_grotassault/` | Mutator strategies, fuzzer anomaly detection, SSRF payloads |
| `test_redteef/` | Payload building, confirmation verdicts |
| `test_waaaghgate/` | Gate policies, blast radius, verification runner, reporting |
| `test_openkrump/` | Spec parsing, schema validation, BOLA |
| `test_cloudstrike/` | AWS recon, IAM pathfinder, S3 auditor (moto mocks) |
| `test_aifuzz/` | Prompt injection, token smuggling, system prompt extraction, response analyzer |
| `test_modelhunt/` | Vector DB scanner, supply chain auditor |
| `test_reposcout/` | Secret scanner, pipeline analyzer, repo crawler |
| `test_core/` | Engine, HTTP client, models, attack chain, HVT scorer, AI orchestrator |
| `test_mcp/` | FastMCP server creation, tool registration, handler logic |

### CI/CD

GitHub Actions runs on Python 3.11, 3.12, and 3.13 with lint + full test suite.


---

## Table of Contents

- [Quick Start](#quick-start)
- [Implementation Backlog](#implementation-backlog)
- [Architecture](#architecture)
- [CLI Commands](#cli-commands)
- [Core Package](#core-package)
- [Modules](#modules)
  - [1. SneakyGits — Recon](#1-sneakygits--recon)
  - [2. BossKey — Auth Modeling](#2-bosskey--auth-modeling)
  - [3. WaaaghLogic — Business Logic Testing](#3-waaaghlogic--business-logic-testing)
  - [4. GrotAssault — Mutation Fuzzing](#4-grotassault--mutation-fuzzing)
  - [5. RedTeef — Exploit Confirmation](#5-redteef--exploit-confirmation)
  - [6. WaaaghGate — CI/CD Integration](#6-waaaghgate--cicd-integration)
  - [7. OpenKrump — API-First Design](#7-openkrump--api-first-design)
- [MCP Server](#mcp-server)
- [Credential Management](#credential-management)
- [Import / Export](#import--export)
- [SDK Generation](#sdk-generation)
- [Configuration](#configuration)
- [Running Tests](#running-tests)

---

## Quick Start

```bash
pip install -e ".[dev,yaml,mcp]"
# or
python3.11 -m pip install -r requirements.txt

# Run a scan
gatekrumpa scan -t http://target.example.com -f json -o ./output/

# List modules
gatekrumpa modules list

# Start MCP server for AI agent integration
gatekrumpa mcp-serve --config configs/default.yaml
```

---

## Implementation Backlog

The working implementation backlog for upcoming capability expansion lives in [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md).

---

## Architecture

```
src/krumpa/
├── core/              # Shared engine, HTTP client, data models, reporting,
│                      #   credentials, exchange, events, recording, scope
├── mcp/               # MCP server (official SDK) — 7 tools for AI agents
├── sneakygits/        # Module 1 — Recon & fingerprinting
├── bosskey/           # Module 2 — Auth & session analysis
├── waaaghlogic/       # Module 3 — Business logic testing
├── grotassault/       # Module 4 — Mutation fuzzing
├── redteef/           # Module 5 — Exploit confirmation
├── waaaghgate/        # Module 6 — CI/CD quality gates
└── openkrump/         # Module 7 — API-first (OpenAPI/Swagger/gRPC)
```

Each module follows a consistent pattern: domain-specific helper classes plus a `module.py` containing a `BaseModule` subclass that orchestrates the helpers within a `ScanContext`.

**Pipeline order:** sneakygits → openkrump → bosskey → waaaghlogic → grotassault → redteef → waaaghgate

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `gatekrumpa scan` | Run a security scan against one or more targets |
| `gatekrumpa modules list` | List all available modules |
| `gatekrumpa modules info <name>` | Show details about a specific module |
| `gatekrumpa report` | Convert saved scan results to a different format |
| `gatekrumpa import` | Import targets from HAR, Burp XML, or ZAP JSON files |
| `gatekrumpa export` | Export recorded traffic to HAR format |
| `gatekrumpa generate-sdk` | Generate a typed Python SDK client from an OpenAPI spec |
| `gatekrumpa mcp-serve` | Start the MCP server (stdio transport) for AI agents |

### Scan flags

```
-t, --target URL          Target URL (repeatable)
--targets-file PATH       File with one URL per line
-m, --modules LIST        Comma-separated module names (default: all)
-c, --config PATH         YAML/JSON config file
--spec URL                OpenAPI spec URL (passed to openkrump)
-f, --format LIST         Output formats: json, sarif, markdown, html, junit
-o, --output DIR          Output directory (default: stdout)
-v / -vv                  Increase verbosity (info / debug)
```

---

## Core Package

`krumpa.core` provides the shared foundation used by every module.

### Data Models (`core/__init__.py`)

| Export | Type | Description |
|--------|------|-------------|
| `Severity` | Enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `ModuleStatus` | Enum | `PENDING`, `RUNNING`, `COMPLETED`, `FAILED` |
| `Target` | Dataclass | Scan target with `url`, `method`, `headers`, `body`, `meta` |
| `Finding` | Dataclass | Vulnerability finding with `title`, `severity`, `description`, `evidence`, `tags`, `confirmed`; method: `to_dict()` |
| `ScanContext` | Dataclass | Shared mutable state holding targets and findings; methods: `add_finding()`, `add_target()`, `summary()` |
| `BaseModule` | ABC | Abstract base for all modules; abstract `run(context)`, plus `setup()`, `teardown()`, `add_finding()`, `reset()` |

### Scan Engine (`core/engine.py`)

| Export | Type | Description |
|--------|------|-------------|
| `ScanEngine` | Class | Registers and runs modules; methods: `register()`, `register_class()`, `run_all()`, `run_module()`, `modules`, `status_report()` |

### HTTP Client (`core/http_client.py`)

| Export | Type | Description |
|--------|------|-------------|
| `HttpClient` | Class | `httpx`-backed async client with retry, rate-limiting, proxy support (HTTP/HTTPS/SOCKS5), certificate handling (CA bundles, client certs, mTLS) |

### Reporting (`core/reporting.py`)

| Function | Format | Description |
|----------|--------|-------------|
| `to_json()` | JSON | Full scan serialization, findings sorted by severity |
| `to_sarif()` | SARIF v2.1.0 | CI/CD-ready SARIF output |
| `to_markdown()` | Markdown | Human-readable report with severity badges |
| `to_html()` | HTML | Self-contained styled report with summary cards and table |
| `to_junit()` | JUnit XML | Findings as `<testcase>` elements grouped by module |

### Additional Core Components

| File | Description |
|------|-------------|
| `credentials.py` | Credential provider chain — env vars, HashiCorp Vault, Azure Key Vault, AWS Secrets Manager |
| `exchange.py` | Import/export converters — HAR 1.2, Burp XML, ZAP JSON |
| `events.py` | EventBus — publish-subscribe with sync/async listeners |
| `recorder.py` | Request recording for traffic capture |
| `scope.py` | Scope management and target filtering |
| `auth.py` | Auth middleware (bearer, API key, basic) |
| `scan_persistence.py` | Checkpoint/resume for long-running scans |
| `scan_isolation.py` | Concurrent scan isolation |

---

## Modules

### 1. SneakyGits — Recon

> Target enumeration, crawling, and fingerprinting.

**Capabilities:** Crawling, content/directory discovery, JS endpoint extraction, JS secret detection, source map detection, SSL/TLS analysis, backup/leftover file detection, WAF/CDN detection, HTTP method discovery, information leakage scanning, authenticated crawl, fingerprint DB (200+ signatures), DNS subdomain enumeration (brute-force/CT logs), platform exposure analysis for Kubernetes, kubelet, etcd, registries, Harbor, Quay, Artifactory, Argo CD, Rancher, and public admin surfaces.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `crawler.py` | `Crawler` | Class | Async web crawler; discovers endpoints via HTML links, robots.txt, sitemaps, JS extraction |
| `fingerprint.py` | `Fingerprinter` | Class | Identifies technologies against a 200+ signature database |
| `platform_exposure.py` | `PlatformExposureAnalyzer` | Class | Safely detects exposed Kubernetes, container, and operational admin surfaces |
| `header_audit.py` | `HeaderAuditor` | Class | Security header analysis |
| `cors_checker.py` | `CorsChecker` | Class | CORS misconfiguration detection |
| `module.py` | `SneakyGitsModule` | BaseModule | Orchestrates recon pipeline |

---

### 2. BossKey — Auth Modeling

> Authentication modeling, session analysis, and credential testing.

**Capabilities:** Password policy, account lockout, session fixation/timeout/invalidation, JWT advanced attacks (key confusion, JWK/jku, kid), OAuth2 analysis, CSRF checker, RBAC matrix, auth scheme enforcement, password reset flow, credential transport audit, token storage analysis, registration flow testing, MFA testing, SAML analysis (XSW/replay/timing/algorithm), remember-me token analysis, concurrent session policy.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `session_analyzer.py` | `SessionAnalyzer` | Class | Cookie and JWT analysis (entropy, flags, algorithm, expiry) |
| `auth_probe.py` | `AuthProbe` | Class | Default credential probing |
| `jwt_attacks.py` | `JwtAttacker` | Class | JWT key confusion, JWK/jku injection, kid attacks |
| `csrf_checker.py` | `CsrfChecker` | Class | CSRF token detection and validation |
| `oauth2_analyzer.py` | `OAuth2Analyzer` | Class | OAuth2 flow analysis |
| `rbac_matrix.py` | `RbacMatrix` | Class | Role-based access control matrix testing |
| `session_fixation.py` | `SessionFixation` | Class | Session fixation detection |
| `session_timeout.py` | `SessionTimeout` | Class | Session timeout validation |
| `lockout_tester.py` | `LockoutTester` | Class | Account lockout policy testing |
| `password_policy.py` | `PasswordPolicy` | Class | Password policy analysis |
| `module.py` | `BossKeyModule` | BaseModule | Orchestrates auth testing pipeline |

---

### 3. WaaaghLogic — Business Logic Testing

> Business logic vulnerability detection.

**Capabilities:** Mass assignment, horizontal/vertical privilege escalation, file upload testing, pagination abuse, idempotency/TOCTOU, flow analysis, data validation bypass, numeric precision abuse, input length boundary, bulk operation abuse, state machine modeling, GraphQL-specific logic, workflow integrity (payment/coupon/gift card), currency rounding exploitation, business-layer rate-limit testing.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `flow_analyzer.py` | `FlowAnalyzer` | Class | Multi-step workflow testing (step-skip, parameter tampering) |
| `idempotency_checker.py` | `IdempotencyChecker` | Class | Duplicate submission and TOCTOU race detection |
| `module.py` | `WaaaghLogicModule` | BaseModule | Orchestrates business logic tests |

---

### 4. GrotAssault — Mutation Fuzzing

> Mutation-based fuzz testing with multi-strategy payload generation.

**Capabilities:** NoSQL/LDAP injection, HTTP smuggling, CRLF/header injection, deserialization payloads, content-type switching, blind injection (OOB), encoding variants, open redirect, path traversal, SSRF/XXE payloads, prototype pollution, HTTP parameter pollution, GraphQL fuzzing, cache poisoning, Unicode normalization, content-type-aware body fuzzing, response fingerprinting, expanded payload DB, WebSocket fuzzing (CSWSH/injection/protocol abuse).

| File | Export | Type | Description |
|------|--------|------|-------------|
| `mutator.py` | `Mutator` | Class | Multi-strategy payload generation (injection, boundary, encoding, format) |
| `fuzzer.py` | `Fuzzer` | Class | Sends payloads and detects anomalies (500s, stack traces, reflection, size deviation, timeouts) |
| `module.py` | `GrotAssaultModule` | BaseModule | Orchestrates fuzzing pipeline |

Payload modules: `nosql_payloads`, `crlf_payloads`, `ssrf_payloads`, `xxe_payloads`, `path_traversal`, `open_redirect`, `smuggling`, `deserialization`, `blind_oob`, `content_type`, `encoding_variants`.

---

### 5. RedTeef — Exploit Confirmation

> Exploit validation and false-positive reduction.

**Capabilities:** Time-based/error-based blind SQLi, OOB verification, environment-aware payloads, canary catalogue (SQLi/XSS/SSTI/CMDi/IDOR/SSRF/XXE/path traversal/open redirect/deserialization), evidence quality scoring, polyglot payloads, regression canaries, multi-step exploit chains.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `payload_builder.py` | `PayloadBuilder` | Class | Builds PoC payloads from canary catalogue |
| `confirmer.py` | `Confirmer` | Class | Executes PoC payloads, evaluates via indicator matching or differential analysis |
| `module.py` | `RedTeefModule` | BaseModule | Selects confirmable findings, runs confirmation, enriches evidence |

---

### 6. WaaaghGate — CI/CD Integration

> Quality-gate policy evaluation and multi-format report generation.

**Capabilities:** Policy-as-code, finding suppression, PR/MR annotations, diff reports, HTML report, SARIF/JUnit output, compliance mapping (OWASP/CWE/PCI DSS/NIST), multiple gate stages, webhook notifications, finding lifecycle states, trend tracking (MTTR), SLA enforcement, badge generation (SVG shields).

| File | Export | Type | Description |
|------|--------|------|-------------|
| `gate.py` | `GatePolicy` | Class | Severity-based quality gate with `ignore_tags` and `total` threshold |
| `reporter.py` | `PipelineReporter` | Class | Multi-format report generation (JSON, SARIF, Markdown) |
| `module.py` | `WaaaghGateModule` | BaseModule | Evaluates policy, generates reports, sets exit code |

---

### 7. OpenKrump — API-First Design

> API spec parsing, validation, and target generation.

**Capabilities:** Swagger 2.0, OpenAPI 3.x, GraphQL schema analysis, mass assignment from spec, response schema validation, excessive data exposure, BOLA generator, deprecation checking, spec auto-discovery, security scheme enforcement (active), parameter constraint testing, spec diff/shadow API detection, gRPC/Protobuf support, example-based testing, API versioning detection, webhook/callback security, server-side validation gaps.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `parser.py` | `SpecParser` | Class | Parses OpenAPI 3.x and Swagger 2.0 specs into endpoints |
| `validator.py` | `SchemaValidator` | Class | Response schema validation, security checks, deprecation detection |
| `bola_generator.py` | `BolaGenerator` | Class | BOLA/IDOR test case generation from spec |
| `excessive_data.py` | `ExcessiveDataDetector` | Class | Excessive data exposure detection |
| `module.py` | `OpenKrumpModule` | BaseModule | Orchestrates API-first testing pipeline |

---

## MCP Server

GateKrumpa includes a Model Context Protocol (MCP) server built on the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) (`FastMCP`). This allows AI agents (Claude, Copilot, etc.) to invoke scan tools directly.

```bash
pip install -e ".[mcp]"
gatekrumpa mcp-serve --config configs/default.yaml
```

### MCP client configuration

```json
{
  "mcpServers": {
    "gatekrumpa": {
      "command": "gatekrumpa",
      "args": ["mcp-serve", "--config", "configs/default.yaml"]
    }
  }
}
```

### Available tools

| Tool | Description |
|------|-------------|
| `gatekrumpa_scan` | Run a security scan against target URLs |
| `gatekrumpa_list_modules` | List all available scan modules |
| `gatekrumpa_module_info` | Get detailed info about a specific module |
| `gatekrumpa_report` | Convert scan results to json/sarif/markdown/html/junit |
| `gatekrumpa_import` | Import targets from HAR/Burp/ZAP files |
| `gatekrumpa_export` | Export recorded traffic to HAR format |
| `gatekrumpa_generate_sdk` | Generate a typed Python SDK from an OpenAPI spec |

All tools accept typed parameters — the SDK auto-generates JSON Schema from function signatures. Credential references (`${VAR}`, `vault://`) are resolved before tool handlers run; agents never see raw secrets.

---

## Credential Management

GateKrumpa resolves secrets via a provider chain — no plaintext credentials in config files.

### Provider chain (priority order)

1. **Environment variables** — `${VAR}` or `${VAR:-default}` syntax, optional prefix
2. **HashiCorp Vault** — `vault://secret/data/path#field`
3. **Azure Key Vault** — `vault://secret-name`
4. **AWS Secrets Manager** — `vault://secret-name#field`

### Configuration

```yaml
credentials:
  env_prefix: "GK_"         # optional: prefix for env var lookups
  vault:
    type: hashicorp          # hashicorp | azure | aws
    addr: "https://vault.example.com"

http:
  auth:
    auth_type: bearer
    token: "${API_TOKEN}"    # resolved from GK_API_TOKEN env var
```

---

## Import / Export

### Import (external → GateKrumpa)

| Format | Command |
|--------|---------|
| HAR 1.2 | `gatekrumpa import -i traffic.har -f har` |
| Burp XML | `gatekrumpa import -i history.xml -f burp` |
| ZAP JSON | `gatekrumpa import -i messages.json -f zap` |

### Export (GateKrumpa → external)

| Format | Command |
|--------|---------|
| HAR 1.2 | `gatekrumpa export -i scan.json -f har` |

---

## SDK Generation

Generate typed Python API clients from OpenAPI/Swagger specs:

```bash
gatekrumpa generate-sdk --spec ./openapi.json -o client.py --class-name MyApiClient
gatekrumpa generate-sdk --spec https://api.example.com/openapi.json -o client.py
```

Supports JSON and YAML specs (YAML requires `pyyaml`). Generates one async method per endpoint with typed parameters.

---

## Configuration

GateKrumpa uses YAML or JSON config files. See `configs/default.yaml` for the full reference.

```yaml
scan:
  modules: [sneakygits, openkrump, bosskey, waaaghlogic, grotassault, redteef, waaaghgate]
  formats: [json, markdown]

http:
  timeout: 30.0
  retries: 3
  verify_ssl: true
  rate_limit: 0.0

sneakygits:
  max_depth: 3
  max_pages: 500

waaaghgate:
  policy:
    fail: { critical: 1, high: 5 }
    warn: { medium: 10 }
    ignore_tags: [accepted-risk]
```

---

## Running Tests

```bash
# All 975 tests
pytest

# Verbose with short tracebacks
pytest -v --tb=short

# Single module
pytest tests/test_sneakygits/
pytest tests/test_bosskey/
pytest tests/test_waaaghlogic/
pytest tests/test_grotassault/
pytest tests/test_redteef/
pytest tests/test_waaaghgate/
pytest tests/test_openkrump/
pytest tests/test_core/
pytest tests/test_mcp/

# Type checking (0 errors, 0 warnings)
pyright src/
```

### Test matrix

| Test directory | Coverage |
|----------------|----------|
| `test_sneakygits/` | Crawling, fingerprinting, header audit, CORS, module orchestration |
| `test_bosskey/` | Session analysis, JWT, auth probing, CSRF, module orchestration |
| `test_waaaghlogic/` | Flow analysis, idempotency, TOCTOU, module orchestration |
| `test_grotassault/` | Mutator strategies, fuzzer anomaly detection, module orchestration |
| `test_redteef/` | Payload building, confirmation verdicts, module orchestration |
| `test_waaaghgate/` | Gate policies, multi-format reporting, module orchestration |
| `test_openkrump/` | Spec parsing, schema validation, BOLA, module orchestration |
| `test_core/` | Engine, HTTP client, models, reporting, credentials, exchange |
| `test_mcp/` | FastMCP server creation, tool registration, handler logic, schema introspection |

### CI/CD

GitHub Actions runs on Python 3.11, 3.12, and 3.13 with lint + full test suite.
