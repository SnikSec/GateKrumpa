# Changelog

All notable changes to GateKrumpa are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-01

### Added

#### New Modules
- **CloudStrike** (`cloudstrike/`) — AWS attack surface analysis module. Handles `aws://` scheme targets via boto3. Sub-components: `AwsRecon` (S3, EC2, IAM, Lambda, ECR, EKS, SageMaker, Bedrock enumeration), `IamPathfinder` (privilege escalation path detection — PassRole, CreatePolicyVersion, AssumeRole chains), `S3Auditor` (public access block, ACL, CORS, encryption, replication), `MetadataServiceAnalyzer` (IMDSv1/v2 + SSRF chain correlation), `CredentialHarvester` (EC2 userdata, Lambda env, ECS, SSM), `DataExfiltrationAnalyzer` (replication rules, pre-signed URL surface), `AiPipelineScanner` (SageMaker notebook internet access, training data exposure, Bedrock logging, model registry). Optional `[cloud]` extra.
- **AiFuzz** (`aifuzz/`) — AI/LLM attack surface testing module. Sub-components: `PromptInjector` (6 injection payloads with canary indicators), `JailbreakTester` (DAN, roleplay, developer mode, nested context, token budget), `TokenSmuggler` (base64, homoglyph, zero-width, token fragmentation, ROT13, leetspeak, reversed, hex-escape), `SystemPromptExtractor` (7 leakage techniques), `GuardrailBypass` (differential analysis + moderation API probing), `IndirectInjector` (HTML comments, markdown table, JSON-LD, YAML frontmatter payloads for RAG), `ResponseAnalyzer` (PII, AWS/GCP/Azure keys, private keys, system prompt structural patterns).
- **ModelHunt** (`modelhunt/`) — AI model analysis and supply chain auditing. Depends on `aifuzz`. Sub-components: `ModelExtractor` (behavioral fingerprinting across 4 probe categories), `MembershipInferenceProber` (verbatim vs. paraphrase completion differential), `PiiExtractor` (7 targeted extraction prompts), `VectorDbScanner` (Qdrant, Weaviate, Chroma, Milvus unauthenticated access), `SupplyChainAuditor` (HuggingFace pickle/safetensors audit, PyPI typosquatting against 10 AI packages, OSV.dev CVE lookup). Optional `[art]` extra for ART text perturbation attacks.
- **RepoScout** (`reposcout/`) — Repository targeting. Handles `github://` and `gitlab://` scheme targets. Sub-components: `RepoCrawler` (GitHub REST+GraphQL, GitLab REST, file tree + CI config collection), `SecretScanner` (13 credential patterns — AWS keys, GitHub tokens, OpenAI/Anthropic keys, DB URLs, private keys, HuggingFace tokens; evidence always redacted), `DependencyAuditor` (requirements.txt, pyproject.toml, package.json, Cargo.toml, go.mod, Gemfile; OSV.dev batch API), `PipelineAnalyzer` (GitHub Actions hardcoded secrets, write-all permissions, unpinned actions, pwn-request risk, AWS creds without OIDC; GitLab CI equivalent), `MlopsScanner` (MLflow URLs, W&B API keys, DVC paths, S3 training URIs, Dockerfile model weights, HuggingFace model ID discovery). Optional `[repo]` extra.

#### Core
- `TargetType` enum (`WEB`, `AWS`, `GITHUB`, `GITLAB`) with `target_type` derived property on `Target` inferred from URL scheme.
- Metadata key conventions documented on `Target`: `aws_profile`, `aws_region`, `repo_token`, `ai_api_key`, `ai_model`, `ai_provider`.
- `AttackChainBuilder` — correlates findings into multi-step attack chains. Eight patterns: SSRF→IMDS, IAM privesc→S3, prompt injection→data leak, repo secret→cloud access, subdomain takeover→session hijack, JWT weakness→RBAC bypass, indirect RAG injection, vector DB→knowledge theft. Stored in `ctx.metadata["attack_chains"]`.
- `HVTScorer` — two-phase high-value target prioritisation. Phase 1: payment/auth/AI fingerprint signals, URL keywords, finding severity, chain participation. Phase 2 (optional AutoGen): contextual LLM reranking. Stored in `ctx.metadata["hvt_scores"]`.
- `TryHarderAgent` — AutoGen-based dead-end alternative technique suggester. Degrades gracefully when `autogen-agentchat` not installed.
- `AttackPlannerAgent` — AutoGen-based next-phase scan planner and HVT reranker.

#### BossKey
- `CloudIdentityAnalyzer` (`bosskey/cloud_identity.py`) — AWS Cognito (user enumeration via password reset, hosted UI open redirect), Azure Entra ID (multi-tenant misconfiguration), Google IAP (JWT backend validation check), PKCE enforcement testing.

#### WaaaghGate
- `BlastRadiusAnalyzer` (`waaaghgate/blast_radius.py`) — contextual severity override: escalates findings in critical blast-radius chains, deprioritises isolated CRITICAL findings, escalates MEDIUM findings on critical HVT assets. Generates Sankey diagram data for HTML report. Wired into `WaaaghGateModule.run()`.
- `VerificationRunner` (`waaaghgate/verification_runner.py`) — stores `VerificationPath` per finding; `verify()` replays the exact exploit path to confirm patch status. Returns `"verified"` / `"patched"` / `"inconclusive"`.

#### SneakyGits
- `FingerprintResult` dataclass — `identify()` now returns rich context (raw headers, body excerpt, cookies, redirect chain) instead of bare `List[str]`. Results stored in `ctx.metadata["fingerprints"]` for downstream modules.
- New fingerprint signatures: AWS ALB/NLB, GKE/GCLB, Azure Front Door, AKS Ingress, Gradio, Streamlit, FastAPI, Triton Inference Server, NVIDIA NIM, Ollama, LangServe, OpenAI-compatible API, Hugging Face Spaces, Prometheus, Grafana, Jaeger, OpenTelemetry, Loki, Kibana, OpenSearch Dashboards.
- `PassiveReconAnalyzer` (`sneakygits/passive_recon.py`) — Wayback Machine CDX API, Common Crawl CDX index, parameter name mining, subdomain takeover detection (GitHub Pages, Heroku, Azure, CloudFront, Fastly, Netlify, Vercel). Wired into `SneakyGitsModule`.
- Extended `PlatformExposureAnalyzer` with Epic 2 admin surfaces (Jenkins, Confluence, Jira, Tomcat Manager, Kafka UI, RabbitMQ, JMX Jolokia, vCenter) and AI/ML surfaces (MLflow, Kubeflow, Triton, Ollama, Gradio, LangServe, OpenAI-compatible API).
- DAST-H1: directory listing detection in `JsExtractor` — emits dedicated `Directory Listing Enabled` finding (CWE-548).
- DAST-H2: JSON body parameter harvesting in `JsExtractor` — field names tagged as `js_discovered_params` in `Target.metadata` for `grotassault`.

#### GrotAssault
- SSRF pivot expansion (Epic 8) — in-cluster Kubernetes service names (`kubernetes.default.svc`, `etcd.kube-system`), internal ML/AI services (MLflow, Kubeflow, Triton), service-account token path indicators. Total SSRF payloads: 46 (up from 25).

#### CLI
- `--aws-profile`, `--aws-region`, `--repo-token`, `--ai-key`, `--ai-model` flags on `gatekrumpa scan`.
- `gatekrumpa verify --finding-id XXXX --input scan.json` — one-click verification command. Exits 1 if finding still exploitable (CI-friendly).

#### MCP
- `gatekrumpa_cloud_scan` — AWS environment scan with region/profile/service filters.
- `gatekrumpa_ai_attack` — AI/LLM endpoint attack with model/key/attack-type selection.
- `gatekrumpa_repo_scan` — GitHub/GitLab repository scan with token support.
- `gatekrumpa_chain_attack` — multi-surface chained scan across mixed target schemes.
- `gatekrumpa_verify` — one-click verification via MCP.
- `gatekrumpa_push_to_tracker` — agentic RBVM: push verified findings to GitHub Issues with full exploit path and remediation.

#### Dependencies
- New optional groups: `[cloud]` (boto3, botocore), `[ai]` (autogen-agentchat, openai), `[art]` (adversarial-robustness-toolbox), `[repo]` (PyGithub, python-gitlab).
- `moto[s3,iam,ec2,sagemaker]` added to `[dev]` for CloudStrike unit tests.

### Changed
- `WaaaghGateModule` now runs `AttackChainBuilder`, `HVTScorer`, and `BlastRadiusAnalyzer` as steps 12–14 of its pipeline.
- `WaaaghGateModule.dependencies` extended to include `cloudstrike`, `aifuzz`, `modelhunt`, `reposcout`.
- `SneakyGitsModule.run()` now stores `FingerprintResult` objects in `ctx.metadata["fingerprints"]` and calls `PassiveReconAnalyzer`.
- Default pipeline extended from 7 to 11 modules.
- `IMPLEMENTATION_BACKLOG.md` replaced by `TODO.md` (consolidated, checkbox-driven).

### Tests
- 975 → 1118 tests (+143). New test directories: `test_cloudstrike/`, `test_aifuzz/`, `test_modelhunt/`, `test_reposcout/`. New test files: `test_core/test_attack_chain.py`, `test_core/test_hvt_scorer.py`, `test_core/test_ai_orchestrator.py`, `test_waaaghgate/test_blast_radius.py`, `test_waaaghgate/test_verification_runner.py`.

## [0.1.0] — 2026-03-04


### Added

#### Core
- Shared `HttpClient` with retry, rate-limiting, scope enforcement, auth injection, and request recording.
- `HttpClientMixin` for clean client wiring across sub-components.
- Certificate handling: CA bundles, client certs, mTLS.
- Cross-module finding deduplication in `ScanContext`.
- Scan state persistence (checkpoint/resume).
- Concurrent scan isolation.

#### SneakyGits (Recon)
- Web crawler with configurable depth and redirect following.
- Content/directory discovery with common wordlists.
- JavaScript endpoint extraction and secret detection.
- Source map detection.
- SSL/TLS certificate analysis.
- Backup/leftover file scanning.
- WAF/CDN detection.
- HTTP method discovery.
- Information leakage scanning.
- Fingerprint DB (200+ signatures).
- DNS subdomain enumeration (brute-force and CT logs).

#### BossKey (Auth)
- Password policy and account lockout testing.
- Session fixation, timeout, and invalidation checks.
- JWT advanced attacks (key confusion, JWK/jku injection, kid manipulation).
- OAuth2 flow analysis.
- CSRF protection auditing.
- RBAC matrix building.
- Auth scheme enforcement.
- Password reset flow testing.
- Credential transport auditing.
- Token storage analysis.
- Registration flow testing.
- MFA bypass testing.
- SAML analysis (XSW, replay, timing, algorithm downgrade).
- Remember-me token analysis.
- Concurrent session policy testing.

#### WaaaghLogic (Business Logic)
- Mass assignment testing.
- Horizontal/vertical privilege escalation detection.
- File upload abuse testing.
- Pagination manipulation.
- Idempotency and TOCTOU race condition testing.
- Workflow flow analysis.
- Data validation bypass (type juggling, special values).
- Numeric precision abuse.
- Input length boundary testing.
- Bulk operation abuse detection.
- State machine modeling.
- GraphQL-specific logic testing.
- Workflow integrity (payment/coupon/gift card tampering).
- Currency rounding exploitation.

#### GrotAssault (Fuzzing)
- SQL/NoSQL/LDAP injection payloads.
- HTTP request smuggling (CL.TE, TE.CL, TE.TE).
- CRLF and header injection.
- Deserialization payloads (Java, PHP, Python, .NET, Ruby).
- Content-type switching and content-type-aware fuzzing.
- Blind/OOB injection detection.
- Encoding variant generation.
- Open redirect testing.
- Path traversal payloads.
- SSRF and XXE payloads.
- Prototype pollution testing.
- HTTP parameter pollution.
- GraphQL query fuzzing.
- Cache poisoning detection.
- Unicode normalization attacks.
- Response fingerprinting and anomaly detection.
- Expanded payload database.
- WebSocket fuzzing (CSWSH, injection, protocol abuse).

#### RedTeef (Confirmation)
- Time-based and error-based blind SQLi confirmation.
- OOB interaction verification.
- Environment-aware payload selection.
- Canary catalogue (SQLi, XSS, SSTI, CMDi, IDOR, SSRF, XXE, path traversal, open redirect, deserialization).
- Dedicated confirmers for path traversal, open redirect, blind XSS, SSRF, XXE, deserialization.
- Evidence quality scoring.
- Polyglot payload testing.
- Regression canaries.
- Multi-step exploit chain building.

#### WaaaghGate (CI/CD)
- Policy-as-code gate (YAML/JSON).
- Finding suppression with expiry.
- PR/MR annotation generation.
- Diff reports between scan runs.
- Self-contained HTML report.
- SARIF and JUnit output.
- Compliance mapping (OWASP Top 10, CWE, PCI DSS, NIST 800-53).
- Multi-stage gate evaluation.
- Webhook notifications (Slack, Discord, Teams, generic).
- Finding lifecycle states.
- Trend tracking with MTTR calculation.
- SLA enforcement.
- SVG badge generation.

#### OpenKrump (API-First)
- OpenAPI 3.x and Swagger 2.0 spec parsing.
- GraphQL schema analysis (introspection, depth/complexity).
- Mass assignment detection from spec.
- Response schema validation.
- Excessive data exposure detection.
- BOLA/IDOR test generation.
- Deprecation checking.
- Spec auto-discovery.
- Security scheme enforcement (active validation).
- Parameter constraint testing (min/max, enum, pattern).
- Spec diff and shadow API detection.
- gRPC/Protobuf support.
- Example-based testing from spec.
- API versioning detection.
- Webhook/callback security analysis.
- Server-side validation gap detection.

#### CLI & Packaging
- `gatekrumpa` CLI entry point via Click.
- YAML config loading (`--config`).
- Module selection (`--modules`).
- GitHub Actions CI (Python 3.11/3.12/3.13, lint, smoke).
- `pyproject.toml` packaging with hatchling.
