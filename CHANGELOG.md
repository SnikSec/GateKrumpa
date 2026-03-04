# Changelog

All notable changes to GateKrumpa are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
