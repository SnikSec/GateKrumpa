# GateKrumpa Implementation Backlog

Working backlog for expanding GateKrumpa against public endpoints, basic apps, gaming services, and cloud-hosted targets on AWS, GCP, Azure, Linux VMs, Kubernetes, and container platforms.

This document consolidates two gap reviews:

1. Gaps identified by comparing GateKrumpa with the broad capability catalog referenced in `S3cur3Th1sSh1t/Pentest-Tools`
2. Gaps identified in GateKrumpa's current coverage for Linux VM, Kubernetes, container, and gaming-service environments

The goal is not to turn GateKrumpa into a post-exploitation framework. The goal is to deepen its external attack-surface discovery, protocol analysis, cloud exposure analysis, and platform-aware testing.

---

## Scope Guardrails

In scope:

- Public web apps and APIs
- Gaming backends and realtime services
- AWS, GCP, Azure-hosted services
- Linux VM-hosted services
- Kubernetes and containerized internet-facing services
- Auth, API, business logic, recon, exposure analysis, and safe exploit confirmation

Out of scope for this backlog:

- Endpoint post-exploitation
- Windows/Linux privilege escalation
- C2 and persistence tooling
- EDR bypass and malware-oriented features
- Lateral movement tooling

---

## Current Gap Summary

GateKrumpa already has strong baseline coverage in web/API/auth recon, GraphQL, gRPC, SSRF metadata checks, business logic, and WebSocket-adjacent testing.

The highest-confidence gaps are:

- Passive recon breadth is limited compared with public bug bounty workflows
- Kubernetes and container exposures are only lightly fingerprinted and not deeply tested
- Cloud storage and cloud identity surfaces are under-tested
- Internet-facing admin/service exposures are not covered by dedicated checks
- Realtime gaming protocols need deeper stateful analysis
- Fingerprinting exists for some Linux/K8s/container services, but active checks lag behind detection

---

## Standard DAST Baseline Coverage

This section tracks whether GateKrumpa covers the normal scope expected from a standard DAST tool.

### 1. Web Application Surface

Status: largely covered

Covered now:

- HTTP and HTTPS target scanning
- Web crawling and endpoint discovery
- HTML page discovery
- REST API target support
- GraphQL endpoint discovery and testing
- URL, query, header, cookie, and body-oriented testing
- Form discovery through crawling

Current implementation signals:

- Crawling and endpoint discovery in `sneakygits`
- OpenAPI, GraphQL, and gRPC handling in `openkrump`
- Payload-based fuzzing in `grotassault`

Still weaker than mature browser-assisted DAST:

- Rich client-side SPA input discovery
- Deep JavaScript-driven workflow mapping
- Passive archived attack-surface expansion

### 2. Common Injection And Input Vulnerabilities

Status: covered as baseline

Covered now:

- SQL injection
- Command injection
- XSS, especially reflected XSS
- Basic SSTI coverage
- XXE when exposed through reachable endpoints
- Additional payload families beyond standard DAST: NoSQL, LDAP, SSRF, CRLF, smuggling, deserialization, path traversal, cache poisoning, GraphQL abuse

Notes:

- This is already one of GateKrumpa's strongest areas
- Stored XSS remains inherently less reliable for automated confirmation than reflected XSS

### 3. Basic Auth And Session Issues

Status: covered, with some depth-dependent partial areas

Covered now:

- Security header analysis
- Cookie flag analysis
- Session fixation
- Session timeout and invalidation checks
- Concurrent session policy checks
- Credential probing and default credential checks
- Authenticated crawling and configured auth providers
- Login and logout endpoint heuristics

Still partial:

- Robust scripted login coverage for highly custom flows
- Rich anti-automation, MFA, and federated login orchestration for every app shape
- Stateful authenticated journey recording comparable to mature enterprise DAST record-and-replay tooling

### 4. API Security

Status: covered for DAST baseline, partial for context-heavy API flaws

Covered now:

- OpenAPI and Swagger parsing
- Spec-driven endpoint generation
- Parameter fuzzing and negative testing
- Injection testing on API inputs
- GraphQL schema analysis and fuzzing
- gRPC and gRPC-Web exposure analysis

Still partial or beyond normal DAST strength:

- High-confidence BOLA and IDOR across real object graphs
- Complex auth choreography
- Multi-step API workflows and business-state dependencies
- Cross-endpoint authorization reasoning

### 5. Configuration Issues

Status: mostly covered, with a few explicit checks to harden

Covered now:

- Missing or weak security headers
- Debug endpoint exposure
- Sensitive and backup file discovery
- Basic default credential checks
- TLS and SSL analysis
- Information leakage in headers and error responses

Still partial:

- Explicit directory-listing detection as a first-class check
- Broader admin-surface fingerprint-to-check mapping for exposed operational products

### 6. Automation-Friendly Logic Checks

Status: stronger than standard DAST in some areas, but still partial for deep workflows

Covered now:

- Basic business logic anomalies
- Rate limiting checks
- Mass assignment
- Idempotency and replay-style issues
- Some IDOR and BOLA-oriented generation and confirmation support
- Flow analysis for step skipping and parameter tampering

Still partial:

- Complex, app-specific multi-actor workflows
- Deep economic abuse and multiplayer state manipulation for gaming services
- High-confidence authorization graph reasoning across large API estates

### DAST Baseline Conclusion

GateKrumpa already covers the core scope expected from a standard DAST tool and, in several areas, exceeds it.

The remaining work is not primarily about achieving baseline DAST parity. The remaining work is about:

- Hardening a few partial baseline areas
- Improving accuracy and routing
- Expanding into cloud-native, Kubernetes, container, and gaming-service-specific testing that normal DAST tools do not cover well

---

## Priority Order

Implement in this order unless a target program pushes a different sequence:

1. Platform exposure checks for Kubernetes, containers, and public admin surfaces
2. Passive recon and attack-surface expansion
3. Cloud storage and cloud identity analysis
4. Realtime gaming protocol analysis
5. Service-mesh and ingress misconfiguration testing
6. Deeper confirmation and chaining for cloud and cluster pivots

---

## DAST Baseline Hardening Backlog

These items close the remaining gaps in standard DAST parity and should be treated as supporting work across the main epics.

### DAST-H1: Explicit Directory Listing Detection

- Add a first-class check for directory indexing responses
- Detect common autoindex patterns across Nginx, Apache, Tomcat, and generic file servers
- Produce a dedicated finding instead of only treating exposed paths as generic discovery results

### DAST-H2: Richer Input Discovery For Modern Frontends

- Expand JavaScript-driven input and route discovery
- Improve harvesting of form fields, JSON body shapes, and parameter candidates from frontend code
- Feed discovered inputs directly into `grotassault` and `openkrump`

### DAST-H3: Scripted Login And Auth Replay Usability

- Improve operator support for recorded or scripted authenticated scans
- Support more repeatable login orchestration for custom forms and token refresh flows
- Preserve session material cleanly for downstream modules

### DAST-H4: API Authorization Baseline Hardening

- Strengthen simple IDOR and BOLA detection outside fully spec-driven APIs
- Improve object identifier mutation heuristics across discovered endpoints
- Route likely authorization-sensitive endpoints into targeted checks automatically

### DAST-H5: Product Exposure Mapping

- When operational products are fingerprinted, automatically run their safe configuration checks
- Elevate from passive detection to explicit "insecurely exposed" findings where evidence supports it

---

## Epic 1: Kubernetes And Container Exposure Analysis

Status: completed in `sneakygits.platform_exposure`

### Why

Current coverage only lightly fingerprints Kubernetes, Docker, and Istio. Publicly exposed cluster and container management surfaces are high-value and common in Linux/K8s environments.

### Deliverables

- Add a dedicated module or submodule family for Kubernetes and container exposure analysis
- Detect and safely probe:
  - Kubernetes API server exposure
  - Kubelet unauthenticated or weakly protected endpoints
  - etcd exposure indicators
  - Kubernetes dashboard exposure
  - Docker Remote API exposure
  - Portainer exposure
  - Public container registry and artifact registry exposure patterns
  - Nomad, Consul, and similar orchestration/control-plane surfaces where applicable
- Detect exposed cluster metadata and management endpoints:
  - `/version`
  - `/api`
  - `/apis`
  - `/healthz`
  - `/livez`
  - `/readyz`
  - `/metrics`
  - `/pods`
  - `/stats/summary`
  - `/debug/pprof`

### Suggested Placement

- Preferred: new module, for example `clusterkrump`
- Acceptable: extend `sneakygits` for discovery and add active checks under `openkrump` or a new platform module

### Acceptance Criteria

- Identifies exposed Kubernetes and container management surfaces with low false positives
- Distinguishes detection from confirmed risky access
- Produces severity by exposure type and access level
- Includes unit tests for detection heuristics and safe probe handling

Implementation notes:

- Implemented in `sneakygits.platform_exposure` and wired through `SneakyGitsModule`
- Covered surfaces now include Kubernetes API server, kubelet, etcd, Kubernetes Dashboard, Docker Engine API, Docker Registry, Portainer, Harbor, Quay, Artifactory, Argo CD, Rancher, Consul, and Nomad
- Covered management endpoints include `/version`, `/api`, `/apis`, `/healthz`, `/livez`, `/readyz`, `/metrics`, `/pods`, `/stats/summary`, and `/debug/pprof/`
- Validated with focused platform exposure tests and the full SneakyGits test suite

---

## Epic 2: Public Admin And Service Exposure Checks

### Why

The comparison repo highlights many common internet-facing products. GateKrumpa fingerprints some of them, but does not yet run dedicated safe checks against likely admin or operational surfaces.

### Deliverables

- Add safe exposure analyzers for common internet-facing services:
  - Jenkins
  - Confluence
  - Jira
  - Tomcat
  - Redis
  - Elasticsearch
  - RabbitMQ management
  - Kafka UI and related admin surfaces
  - Prometheus
  - Grafana
  - Kibana
  - Docker API
  - JMX exposure
  - vCenter and similar operational panels when publicly reachable
- For each service, implement checks for:
  - Anonymous access
  - Version disclosure
  - Default or diagnostic endpoints
  - Misconfiguration indicators
  - Known unsafe exposure patterns that can be tested safely

### Suggested Placement

- `sneakygits` for exposure discovery and service fingerprinting
- New helper package for service-specific checks

### Acceptance Criteria

- A discovered service gets both a fingerprint and a focused safety check pass
- Findings clearly separate "service detected" from "service exposed insecurely"
- Tests cover positive and negative examples for each supported service family

---

## Epic 3: Passive Recon Expansion

### Why

Current recon is strong on live crawling and direct discovery, but weaker on passive attack-surface collection than common external testing workflows.

### Deliverables

- Add archived URL gathering:
  - Wayback Machine
  - Common Crawl-derived sources where practical
  - AlienVault OTX-style known URL sources if practical
- Add parameter discovery and enrichment:
  - Parameter name mining from JS bundles
  - Archived URL parameter extraction
  - Common parameter heuristics per framework
  - Reflection-assisted candidate generation
- Add optional screenshotting or visual triage of discovered apps and panels
- Add subdomain takeover and dangling DNS analysis for common platforms:
  - GitHub Pages
  - Heroku
  - Azure-hosted aliases
  - CloudFront
  - Fastly
  - Netlify
  - Vercel

### Suggested Placement

- `sneakygits`

### Acceptance Criteria

- Passive findings merge into `ScanContext` without duplicating live crawl results excessively
- Parameter candidates feed later fuzzing and auth/business-logic modules
- Takeover checks include clear evidence for dangling-resource conditions

---

## Epic 4: Cloud Storage Exposure Analysis

### Why

For AWS, GCP, and Azure-hosted apps, object storage exposure is a routine and high-value issue. GateKrumpa fingerprints some cloud platforms but does not actively analyze storage exposure deeply.

### Deliverables

- Add checks for public and weakly protected storage:
  - AWS S3 buckets
  - Azure Blob containers
  - Google Cloud Storage buckets
- Detect:
  - Public listing enabled
  - Public object access
  - Predictable bucket naming tied to discovered domains/subdomains
  - Leaked signed URL patterns
  - Over-permissive CORS on storage origins
  - Exposure of backups, media, patch assets, and game bundle content

### Suggested Placement

- New cloud package or `sneakygits` plus `redteef` confirmation helpers

### Acceptance Criteria

- Bucket and container checks are safe and read-only
- Findings identify storage type, access pattern, and object/listing status
- Discovery is tied back to the originating app or domain where possible

---

## Epic 5: Cloud Identity And Hosted Auth Surface Analysis

### Why

OAuth2/OIDC coverage exists, but cloud identity surfaces are broader than standard authorization-server metadata. Modern hosted apps often use Cognito, Entra ID, IAP, Auth0-like patterns, or bespoke cloud gateway auth.

### Deliverables

- Extend auth analysis for cloud-hosted identity surfaces:
  - AWS Cognito user pools and hosted UI patterns
  - Azure Entra ID / Microsoft identity platform tenant flows
  - Google Identity / IAP edge cases
  - Public OIDC metadata and callback-domain drift analysis
- Add checks for:
  - Tenant and issuer mismatch
  - Permissive callback and logout URI behavior
  - Weak PKCE or public-client handling
  - Mis-scoped APIs or broad default scopes
  - Token audience and issuer confusion

### Suggested Placement

- `bosskey`

### Acceptance Criteria

- New checks integrate with existing OAuth2/OIDC logic cleanly
- Findings remain focused on externally testable auth misconfiguration
- Coverage includes at least AWS, Azure, and GCP identity patterns

---

## Epic 6: Realtime Gaming Protocol Analysis

### Why

Gaming backends frequently depend on WebSockets, gRPC, JSON message buses, and low-latency APIs. Current coverage exists, but it is still mostly request/response oriented.

### Deliverables

- Deepen WebSocket analysis:
  - Real session establishment, not only upgrade probing
  - Message-level authorization checks
  - Replay and sequence abuse
  - Room, lobby, or channel access control checks
  - Duplicate event and race-condition tests
- Deepen gRPC analysis:
  - Streaming RPC handling where practical
  - Method-level authz inference
  - Replay and duplicate action handling
  - Better proto-derived negative testing
- Add optional protocol patterns for gaming APIs:
  - Matchmaking
  - Inventory updates
  - Currency or reward mutation flows
  - Session resume and reconnect abuse

### Suggested Placement

- `grotassault` for active protocol fuzzing
- `waaaghlogic` for flow and state abuse
- `openkrump` for gRPC and API surface understanding

### Acceptance Criteria

- Can maintain protocol session state across multiple messages or calls
- Can model action ordering and replay-sensitive operations
- Produces targeted findings for common game-service logic flaws

---

## Epic 7: Service Mesh, Ingress, And Edge Routing Tests

### Why

Current fingerprinting detects Envoy, Traefik, Istio, and some gateway products, but there are few active checks for exposed admin interfaces, route leakage, or host-header/routing mistakes.

### Deliverables

- Add checks for:
  - Envoy admin and debug exposure
  - Traefik dashboard exposure
  - Istio config or debug endpoints
  - Alternate host and route probing
  - Header-based routing bypass attempts
  - Internal route leakage through gateway misconfiguration
  - Metrics and tracing surfaces exposed at the edge

### Suggested Placement

- `sneakygits` for discovery
- new platform/edge helper package for active checks

### Acceptance Criteria

- Correctly identifies public edge infrastructure and tests only safe admin surfaces
- Supports host-header and routing-variant probes without destabilizing scans

---

## Epic 8: Kubernetes And Cloud SSRF Pivot Expansion

### Why

Current SSRF confirmation already checks cloud metadata endpoints well. The next step is to cover in-cluster and internal service pivot patterns relevant to cloud-native deployments.

### Deliverables

- Extend SSRF payloads and confirmation for:
  - In-cluster Kubernetes service names
  - Common control-plane hostnames
  - Internal Prometheus, Grafana, Kibana, Elasticsearch, Redis, and admin URLs
  - Service-account token path indicators where externally testable and safe
  - Internal DNS rebinding and alternate IP representation variants relevant to cluster environments

### Suggested Placement

- `grotassault` payload expansion
- `redteef` confirmation expansion

### Acceptance Criteria

- SSRF checks can distinguish generic SSRF from cloud metadata exposure and cluster pivot potential
- Evidence is specific enough for remediation and triage

---

## Epic 9: Fingerprinting Normalization And Depth

### Why

The codebase currently has both a lightweight fingerprinter and an extended fingerprint database. Active checks should consistently benefit from the richer fingerprint context.

### Deliverables

- Normalize fingerprint collection so extended detection always has access to:
  - Real response headers
  - Representative response body excerpts
  - Cookies and redirect metadata
- Expand Linux/K8s/container fingerprints for:
  - NGINX Ingress
  - AWS ALB and NLB HTTP patterns where visible
  - GKE and GCLB indicators
  - Azure Application Gateway and Front Door nuances
  - EKS, GKE, AKS-related edge behavior where externally fingerprintable
  - Portainer, Harbor, Argo CD, Grafana, Prometheus, Loki, Jaeger, Kibana, OpenSearch

### Suggested Placement

- `sneakygits`

### Acceptance Criteria

- Downstream modules can consume richer fingerprint context from `ScanContext`
- Fingerprint data improves routing into module-specific checks

---

## Epic 10: Risk-Based Scan Routing

### Why

As platform-aware checks grow, GateKrumpa should not run every probe against every target. Routing based on fingerprints and discovered assets will reduce noise and improve performance.

### Deliverables

- Add a routing layer that activates checks based on observed signals:
  - gRPC found → run gRPC analyzer and protocol tests
  - Kubernetes indicators found → run cluster exposure analyzer
  - Storage origin found → run cloud storage checks
  - Realtime endpoints found → run WebSocket/gaming protocol checks
  - Admin-service fingerprints found → run service exposure analyzer
- Track confidence and rationale for why a sub-check was activated

### Acceptance Criteria

- Scan time remains bounded as capability surface expands
- Reports include which specialized analyzers were triggered and why

---

## Implementation Phases

### Phase 1: Highest Yield

- Epic 1: Kubernetes And Container Exposure Analysis
- Epic 2: Public Admin And Service Exposure Checks
- Epic 3: Passive Recon Expansion
- Epic 9: Fingerprinting Normalization And Depth

### Phase 2: Cloud And Hosted Platforms

- Epic 4: Cloud Storage Exposure Analysis
- Epic 5: Cloud Identity And Hosted Auth Surface Analysis
- Epic 8: Kubernetes And Cloud SSRF Pivot Expansion

### Phase 3: Gaming And Realtime Depth

- Epic 6: Realtime Gaming Protocol Analysis
- Epic 7: Service Mesh, Ingress, And Edge Routing Tests
- Epic 10: Risk-Based Scan Routing

---

## Initial Work Breakdown

### Backlog A: Discovery Foundations

- Unify response capture for fingerprinting
- Add passive URL collectors
- Add parameter candidate mining
- Add subdomain takeover logic
- Add screenshot support

### Backlog B: Platform Exposure Foundations

- Add Kubernetes exposure detectors
- Add Docker and container admin surface checks
- Add Prometheus, Grafana, Kibana, Jenkins, Redis, Elasticsearch safe exposure checks

### Backlog C: Cloud Foundations

- Add S3, Azure Blob, and GCS exposure analysis
- Extend OAuth2/OIDC checks for cloud identity patterns
- Extend SSRF cluster and cloud pivot payloads

### Backlog D: Gaming Protocol Foundations

- Implement stateful WebSocket sessions
- Extend gRPC beyond unary probing
- Add replay, ordering, duplicate-action, and channel authz checks

---

## Testing Expectations

Every backlog item should ship with:

- Unit tests for heuristics and parsing
- Mocked positive and negative HTTP cases
- Safety-focused tests that ensure probes stay read-only where intended
- Regression tests for false-positive-prone fingerprints
- README updates if the feature changes operator-facing behavior

---

## Suggested First Milestone

If implementation starts immediately, the first milestone should include:

1. Fingerprint normalization improvements
2. Kubernetes and Docker exposure discovery
3. Prometheus, Grafana, Redis, Elasticsearch, and Jenkins public exposure checks
4. Passive archived URL and parameter discovery
5. Subdomain takeover detection

This milestone would materially improve GateKrumpa for cloud-hosted public apps and gaming backends without requiring major architectural change.