# GateKrumpa

A modular dynamic attack simulation platform for external APIs and game services.

**Version:** 0.1.0 · **Codename:** GateKrumpa · **284 tests passing**

---

## Table of Contents

- [Architecture](#architecture)
- [Core Package](#core-package)
- [Modules](#modules)
  - [1. SneakyGits — Recon](#1-sneakygits--recon)
  - [2. BossKey — Auth Modeling](#2-bosskey--auth-modeling)
  - [3. WaaaghLogic — Business Logic Testing](#3-waaaghlogic--business-logic-testing)
  - [4. GrotAssault — Mutation Fuzzing](#4-grotassault--mutation-fuzzing)
  - [5. RedTeef — Exploit Confirmation](#5-redteef--exploit-confirmation)
  - [6. WaaaghGate — CI/CD Integration](#6-waaaghgate--cicd-integration)
  - [7. OpenKrump — API-First Design](#7-openkrump--api-first-design)
- [Running Tests](#running-tests)

---

## Architecture

```
src/krumpa/
├── core/              # Shared engine, HTTP client, data models, reporting
├── sneakygits/        # Module 1 — Recon
├── bosskey/           # Module 2 — Auth Modeling
├── waaaghlogic/       # Module 3 — Business Logic Testing
├── grotassault/       # Module 4 — Mutation Fuzzing
├── redteef/           # Module 5 — Exploit Confirmation
├── waaaghgate/        # Module 6 — CI/CD Integration
└── openkrump/         # Module 7 — API-First Design
```

Each module follows a consistent pattern: one or two domain-specific helper classes plus a `module.py` containing a `BaseModule` subclass that orchestrates the helpers within a `ScanContext`.

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
| `HttpClient` | Class | `httpx`-backed async client with retry logic, rate-limiting, and proxy support; methods: `request()`, `get()`, `post()`, `put()`, `delete()`, `close()` |

### Reporting (`core/reporting.py`)

| Export | Type | Description |
|--------|------|-------------|
| `to_json()` | Function | Serialize findings to JSON |
| `to_sarif()` | Function | Serialize findings to SARIF format |
| `to_markdown()` | Function | Render findings as a Markdown report |

---

## Modules

### 1. SneakyGits — Recon

> Target enumeration, crawling, and fingerprinting.

Discovers endpoints by following HTML links, parsing `robots.txt`, and extracting sitemap URLs, then fingerprints each target against a signature database.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `crawler.py` | `Crawler` | Class | Async web crawler; method: `crawl() → List[str]` — discovers endpoints via HTML links, robots.txt, and sitemaps |
| `fingerprint.py` | `Fingerprinter` | Class | Identifies technologies; method: `identify() → List[str]` — matches HTTP responses against a signature database |
| `module.py` | `SneakyGitsModule` | BaseModule | Orchestrates crawl + fingerprint and records findings |

#### Tests — `test_sneakygits/` (43 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_crawler.py` | `TestCrawlerHelpers` | `test_normalize_url`, `test_normalize_with_fragment`, `test_normalize_trailing_slash`, `test_is_same_domain_true`, `test_is_same_domain_false`, `test_extract_links`, `test_extract_links_skips_external`, `test_extract_links_relative`, `test_parse_robots_txt`, `test_parse_robots_disallowed`, `test_parse_sitemap_xml`, `test_parse_sitemap_nested` |
| `test_crawler.py` | `TestCrawlItem` | `test_crawl_item_depth` |
| `test_crawler.py` | `TestCrawlerCrawl` | `test_crawl_single_page`, `test_crawl_follows_links`, `test_crawl_respects_max_depth`, `test_crawl_respects_max_pages`, `test_crawl_skips_visited`, `test_crawl_includes_robots`, `test_crawl_includes_sitemap`, `test_crawl_handles_errors` |
| `test_fingerprint.py` | `TestFingerprinterMatches` | `test_server_header_match`, `test_x_powered_by_match`, `test_body_signature_match`, `test_no_match`, `test_multiple_matches`, `test_case_insensitive` |
| `test_fingerprint.py` | `TestFingerprinterIdentify` | `test_identify_returns_techs`, `test_identify_deduplicates`, `test_identify_multiple_urls`, `test_identify_handles_http_error`, `test_identify_empty_list`, `test_identify_records_headers`, `test_identify_body_match`, `test_identify_no_match` |
| `test_module.py` | `TestSneakyGitsModule` | `test_run_populates_findings`, `test_run_no_targets`, `test_adds_crawled_targets`, `test_fingerprint_results_in_evidence`, `test_name`, `test_description`, `test_module_reset`, `test_crawl_error_handled` |

---

### 2. BossKey — Auth Modeling

> Authentication modeling and session analysis.

Analyses cookies and JWT tokens for security weaknesses (entropy, flags, algorithm, expiry) and probes authentication endpoints with default credentials.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `session_analyzer.py` | `CookieInfo` | Dataclass | Parsed cookie metadata |
| `session_analyzer.py` | `JWTInfo` | Dataclass | Decoded JWT metadata |
| `session_analyzer.py` | `SessionAnalyzer` | Class | Methods: `analyse_cookies()`, `analyse_tokens()`, `parse_cookie()`, `decode_jwt()`, `shannon_entropy()` |
| `auth_probe.py` | `AuthEndpoint` | Dataclass | Authentication endpoint descriptor |
| `auth_probe.py` | `AuthProbe` | Class | Probes auth endpoints with default creds; method: `probe() → List[Finding]` |
| `module.py` | `BossKeyModule` | BaseModule | Orchestrates session analysis + auth probing |

#### Tests — `test_bosskey/` (50 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_session_analyzer.py` | `TestShannonEntropy` | `test_zero_entropy_single_char`, `test_max_entropy_binary`, `test_medium_entropy`, `test_empty_string` |
| `test_session_analyzer.py` | `TestParseCookie` | `test_basic_cookie`, `test_secure_httponly_flags`, `test_samesite_attribute`, `test_missing_flags` |
| `test_session_analyzer.py` | `TestAnalyseCookies` | `test_flags_missing_secure`, `test_flags_missing_httponly`, `test_flags_low_entropy`, `test_clean_cookie`, `test_multiple_cookies`, `test_samesite_none_warning`, `test_empty_cookies_list` |
| `test_session_analyzer.py` | `TestDecodeJwt` | `test_decodes_valid_jwt`, `test_detects_none_algorithm`, `test_missing_exp`, `test_expired_token`, `test_invalid_format` |
| `test_session_analyzer.py` | `TestAnalyseTokens` | `test_flags_none_algorithm`, `test_flags_missing_exp`, `test_clean_token`, `test_flags_expired_token`, `test_multiple_tokens`, `test_empty_tokens_list` |
| `test_auth_probe.py` | `TestDefaultCreds` | `test_default_creds_not_empty`, `test_cred_structure` |
| `test_auth_probe.py` | `TestProbeSuccess` | `test_flags_successful_login`, `test_ignores_failed_login`, `test_multiple_endpoints` |
| `test_auth_probe.py` | `TestProbeEdge` | `test_handles_http_error`, `test_custom_success_codes`, `test_empty_endpoints`, `test_custom_credentials` |
| `test_auth_probe.py` | `TestBuildRequests` | `test_form_body`, `test_json_body` |
| `test_module.py` | `TestBossKeyModule` | `test_run_analyses_cookies`, `test_run_probes_auth`, `test_no_targets`, `test_combined_findings`, `test_name`, `test_description`, `test_session_errors_handled`, `test_probe_errors_handled`, `test_module_reset` |

---

### 3. WaaaghLogic — Business Logic Testing

> Business logic vulnerability detection.

Tests multi-step workflows for step-skip and parameter-tampering vulnerabilities, and checks endpoints for idempotency violations and TOCTOU race conditions.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `flow_analyzer.py` | `WorkflowStep` | Dataclass | A single step in a multi-step workflow |
| `flow_analyzer.py` | `FlowAnalyzer` | Class | Tests workflows for step-skip and tamper vulnerabilities; method: `test_workflow() → List[Finding]`; uses `DEFAULT_TAMPER_VALUES` |
| `idempotency_checker.py` | `IdempotencyChecker` | Class | Detects duplicate-submission and TOCTOU race conditions; method: `check() → List[Finding]` |
| `module.py` | `WaaaghLogicModule` | BaseModule | Orchestrates workflow analysis + idempotency checks |

#### Tests — `test_waaaghlogic/` (30 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_flow_analyzer.py` | `TestStepSkip` | `test_detects_skip_allowed`, `test_no_skip_when_blocked`, `test_single_step_no_skip` |
| `test_flow_analyzer.py` | `TestTamperDetection` | `test_detects_tamper_vuln`, `test_no_tamper_when_unchanged`, `test_custom_tamper_values` |
| `test_flow_analyzer.py` | `TestWorkflowEdgeCases` | `test_empty_workflow`, `test_http_error_handled`, `test_all_steps_tested` |
| `test_flow_analyzer.py` | `TestWorkflowStepDataclass` | `test_step_fields`, `test_step_defaults`, `test_step_with_body`, `test_step_with_headers` |
| `test_idempotency_checker.py` | `TestDuplicateSubmission` | `test_detects_duplicate_accepted`, `test_no_finding_when_rejected`, `test_handles_http_error` |
| `test_idempotency_checker.py` | `TestToctouRace` | `test_detects_race_condition`, `test_no_race_when_consistent` |
| `test_idempotency_checker.py` | `TestIdempotencyEdge` | `test_empty_targets`, `test_get_requests_skipped`, `test_multiple_targets` |
| `test_module.py` | `TestWaaaghLogicModule` | `test_runs_flow_analysis`, `test_runs_idempotency_check`, `test_no_targets`, `test_combined_findings`, `test_name`, `test_description`, `test_workflows_from_context`, `test_module_reset`, `test_error_handling` |

---

### 4. GrotAssault — Mutation Fuzzing

> Mutation-based fuzz testing.

Generates mutated payloads across injection, boundary, encoding, and format strategies, then fuzzes endpoints looking for 500-level errors, stack traces, reflected input, size deviations, and slow responses.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `mutator.py` | `MutationStrategy` | Enum | `INJECTION`, `BOUNDARY`, `ENCODING`, `FORMAT`, `ALL` |
| `mutator.py` | `Mutator` | Class | Generates fuzz payloads; methods: `generate(strategy) → List[str]`, `generate_for_dict(data, strategy) → List[Dict]` |
| `fuzzer.py` | `FuzzTarget` | Dataclass | A fuzz target descriptor |
| `fuzzer.py` | `Fuzzer` | Class | Sends mutated payloads and detects anomalies; method: `fuzz() → List[Finding]` — detects 500+ errors, stack traces, reflected input, size deviations, slow responses |
| `module.py` | `GrotAssaultModule` | BaseModule | Orchestrates fuzzing across explicit targets and auto-detected endpoints; helper: `_extract_body()` |

#### Tests — `test_grotassault/` (42 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_mutator.py` | `TestInjectionPayloads` | `test_sql_payloads_present`, `test_xss_payloads_present`, `test_command_payloads_present` |
| `test_mutator.py` | `TestBoundaryPayloads` | `test_long_strings`, `test_negative_numbers`, `test_empty_values` |
| `test_mutator.py` | `TestEncodingPayloads` | `test_unicode_payloads`, `test_null_bytes` |
| `test_mutator.py` | `TestGenerateForDict` | `test_produces_variations`, `test_preserves_other_keys`, `test_empty_dict`, `test_strategy_filtering`, `test_all_strategy`, `test_nested_dict` |
| `test_fuzzer.py` | `TestStatusCodeDetection` | `test_detects_500_error`, `test_ignores_200_response` |
| `test_fuzzer.py` | `TestStackTraceDetection` | `test_detects_python_traceback`, `test_detects_java_stack_trace` |
| `test_fuzzer.py` | `TestReflectedInput` | `test_detects_reflected_payload`, `test_no_reflection` |
| `test_fuzzer.py` | `TestSizeDeviation` | `test_detects_large_deviation`, `test_ignores_small_deviation` |
| `test_fuzzer.py` | `TestSlowResponse` | `test_detects_slow_response`, `test_normal_speed` |
| `test_fuzzer.py` | `TestFuzzIntegration` | `test_fuzz_returns_findings`, `test_fuzz_multiple_targets` |
| `test_fuzzer.py` | `TestFuzzEdgeCases` | `test_http_error_handled`, `test_empty_targets`, `test_custom_timeout` |
| `test_module.py` | `TestGrotAssaultModule` | `test_runs_fuzzer`, `test_no_targets`, `test_name`, `test_description`, `test_module_reset` |
| `test_module.py` | `TestAutoDetection` | `test_auto_detects_fuzzable_params`, `test_no_params_no_auto_targets` |
| `test_module.py` | `TestExtractBody` | `test_extracts_json_body`, `test_extracts_form_body`, `test_returns_none_for_empty` |
| `test_module.py` | `TestModuleFindings` | `test_findings_added_to_module` |

---

### 5. RedTeef — Exploit Confirmation

> Exploit validation and confirmation.

Validates suspected vulnerabilities with safe PoC requests, confirms or dismisses findings from other modules (reducing false positives), and produces evidence payloads and impact assessments.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `payload_builder.py` | `ProofPayload` | Dataclass | A single PoC payload plus metadata (vuln_type, payload, expected_indicator, is_regex, inject location/field) |
| `payload_builder.py` | `PayloadBuilder` | Class | Builds confirmation payloads from a canary catalogue for sqli, xss, ssti, cmdi, idor; methods: `build()`, `infer_vuln_type()`; property: `supported_types` |
| `confirmer.py` | `ConfirmationVerdict` | Enum | `CONFIRMED`, `LIKELY`, `NOT_CONFIRMED` |
| `confirmer.py` | `ConfirmationResult` | Dataclass | Outcome of a confirmation attempt (verdict, evidence_payloads, response_snippets, notes); properties: `.confirmed`, `.likely` |
| `confirmer.py` | `Confirmer` | Class | Executes PoC payloads and evaluates results via indicator matching or differential analysis; methods: `confirm()`, `confirm_sqli_differential()` |
| `module.py` | `RedTeefModule` | BaseModule | Selects confirmable findings, builds payloads, runs confirmation, promotes confirmed/likely findings with enriched evidence |
| `module.py` | `_lower_severity()` | Function | Drops severity by one level for "likely" findings |

#### Tests — `test_redteef/` (40 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_payload_builder.py` | `TestSupportedTypes` | `test_has_common_types`, `test_extra_canaries_extend_catalogue` |
| `test_payload_builder.py` | `TestBuild` | `test_returns_payloads_for_known_type`, `test_returns_empty_for_unknown_type`, `test_sets_inject_field`, `test_sets_http_method`, `test_sets_inject_location`, `test_xss_canaries_have_expected_indicator`, `test_ssti_canaries_expect_1337` |
| `test_payload_builder.py` | `TestInferVulnType` | `test_infers_sqli_from_tags`, `test_infers_xss_from_tags`, `test_infers_from_title`, `test_infers_ssti_from_tags`, `test_infers_cmdi_from_tags`, `test_infers_idor_from_tags`, `test_returns_none_for_unknown` |
| `test_confirmer.py` | `TestIndicatorConfirmation` | `test_confirmed_when_indicator_found`, `test_not_confirmed_when_indicator_missing`, `test_likely_when_partial_match`, `test_no_payloads_returns_not_confirmed`, `test_regex_indicator`, `test_evidence_snippets_populated` |
| `test_confirmer.py` | `TestSqliDifferential` | `test_confirmed_on_status_diff`, `test_confirmed_on_body_size_diff`, `test_likely_on_small_body_diff`, `test_not_confirmed_identical_responses` |
| `test_confirmer.py` | `TestInjectLocations` | `test_body_injection`, `test_header_injection`, `test_url_injection` |
| `test_module.py` | `TestConfirmationFlow` | `test_confirms_xss_when_indicator_reflected`, `test_no_confirmation_when_indicator_absent`, `test_skips_info_findings`, `test_skips_already_confirmed`, `test_empty_context_returns_empty` |
| `test_module.py` | `TestFieldInference` | `test_infers_field_from_evidence` |
| `test_module.py` | `TestModuleMetadata` | `test_name`, `test_description` |
| `test_module.py` | `TestLowerSeverity` | `test_critical_becomes_high`, `test_high_becomes_medium`, `test_info_stays_info` |

---

### 6. WaaaghGate — CI/CD Integration

> Quality-gate policy evaluation, SARIF/JSON/Markdown report generation, and exit-code determination for pipeline integration.

Evaluates scan findings against configurable severity thresholds (fail/warn), generates multi-format reports, and returns an exit code suitable for CI/CD pipelines.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `gate.py` | `PolicyViolation` | Dataclass | A single threshold breach (severity, count, threshold, message) |
| `gate.py` | `GateResult` | Dataclass | Quality-gate outcome (passed, violations, warnings, summary); property: `.exit_code` |
| `gate.py` | `GatePolicy` | Class | Configurable severity-based quality gate; method: `evaluate(findings) → GateResult`; supports `ignore_tags` and `total` threshold |
| `reporter.py` | `ReportFormat` | Enum | `JSON`, `SARIF`, `MARKDOWN` |
| `reporter.py` | `PipelineReporter` | Class | Generates pipeline-friendly reports; method: `generate(findings, gate_result, ctx) → Dict[ReportFormat, str]` |
| `module.py` | `WaaaghGateModule` | BaseModule | Evaluates gate policy, generates reports, stores results in context metadata; produces no new findings |

#### Tests — `test_waaaghgate/` (37 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_gate.py` | `TestGatePolicyDefaults` | `test_passes_with_no_findings`, `test_fails_on_one_critical`, `test_allows_up_to_five_high`, `test_fails_on_six_high` |
| `test_gate.py` | `TestCustomPolicy` | `test_custom_thresholds`, `test_total_threshold`, `test_total_threshold_passes` |
| `test_gate.py` | `TestWarnings` | `test_warn_threshold`, `test_no_warning_below_threshold` |
| `test_gate.py` | `TestIgnoreTags` | `test_ignores_tagged_findings`, `test_does_not_ignore_untagged` |
| `test_gate.py` | `TestGateResult` | `test_summary_contains_status`, `test_summary_contains_failed`, `test_violations_have_message` |
| `test_reporter.py` | `TestJsonReport` | `test_valid_json`, `test_includes_gate_result`, `test_includes_scan_context`, `test_empty_findings` |
| `test_reporter.py` | `TestSarifReport` | `test_valid_sarif_structure`, `test_findings_as_results`, `test_severity_mapping`, `test_low_severity_is_note`, `test_location_from_target` |
| `test_reporter.py` | `TestMarkdownReport` | `test_contains_header`, `test_contains_table_row`, `test_gate_pass_status`, `test_gate_fail_status`, `test_empty_findings` |
| `test_reporter.py` | `TestMultiFormat` | `test_generates_all_requested_formats` |
| `test_module.py` | `TestWaaaghGateModule` | `test_returns_no_new_findings`, `test_gate_result_stored`, `test_gate_passes_clean_scan`, `test_reports_generated`, `test_context_metadata_updated`, `test_context_metadata_on_failure`, `test_custom_policy`, `test_module_metadata` |

---

### 7. OpenKrump — API-First Design

> Parse OpenAPI/Swagger specs, auto-generate targets from spec endpoints, validate API responses against declared schemas, detect undocumented endpoints and missing security definitions.

Supports both OpenAPI 3.x and Swagger 2.0 specs. Parses endpoints, registers them as scan targets, performs security and deprecation checks, and sends live requests for schema validation.

| File | Export | Type | Description |
|------|--------|------|-------------|
| `parser.py` | `ParsedEndpoint` | Dataclass | API endpoint extracted from an OpenAPI spec (path, method, operation_id, parameters, request_body_schema, response_schemas, security, tags, deprecated); property: `.full_id` |
| `parser.py` | `SpecParser` | Class | Parses OpenAPI 3.x and Swagger 2.0 specs; methods: `parse() → List[ParsedEndpoint]`, `resolve_url()`; property: `base_url` |
| `validator.py` | `ValidationIssue` | Dataclass | A single schema/security validation issue (endpoint, issue_type, detail, severity); property: `.summary` |
| `validator.py` | `SchemaValidator` | Class | Validates API responses against schemas; methods: `validate_response()`, `check_security()`, `check_deprecated()`, `issues_to_findings()` |
| `module.py` | `OpenKrumpModule` | BaseModule | Obtains spec (inline or via URL), parses endpoints, registers targets, performs security/deprecation checks, sends live requests for schema validation |

#### Tests — `test_openkrump/` (42 tests)

| File | Test Class | Tests |
|------|------------|-------|
| `test_parser.py` | `TestOpenAPI3Parsing` | `test_parses_endpoints`, `test_method_and_path`, `test_operation_id`, `test_parameters`, `test_request_body_schema`, `test_response_schema`, `test_security_inheritance`, `test_operation_level_security_override`, `test_deprecated_flag`, `test_tags` |
| `test_parser.py` | `TestSwagger2Parsing` | `test_parses_endpoints`, `test_request_body_from_body_param`, `test_response_schema` |
| `test_parser.py` | `TestResolveUrl` | `test_openapi3_server`, `test_swagger2_url`, `test_base_url_override`, `test_empty_spec_fallback` |
| `test_validator.py` | `TestValidateResponse` | `test_valid_object`, `test_type_mismatch_at_root`, `test_missing_required_field`, `test_nested_type_mismatch`, `test_array_validation`, `test_array_type_mismatch`, `test_undocumented_status_code`, `test_no_schema_at_all` |
| `test_validator.py` | `TestStrictMode` | `test_flags_extra_fields`, `test_no_extra_flags_non_strict` |
| `test_validator.py` | `TestSecurityChecks` | `test_flags_no_security`, `test_passes_with_security` |
| `test_validator.py` | `TestDeprecatedCheck` | `test_flags_deprecated`, `test_not_deprecated` |
| `test_validator.py` | `TestIssuesToFindings` | `test_converts_issues`, `test_empty_issues` |
| `test_module.py` | `TestOpenKrumpModule` | `test_parses_and_adds_targets`, `test_flags_missing_security`, `test_validates_response_schema`, `test_clean_response_no_schema_issues`, `test_no_spec_returns_empty`, `test_module_metadata`, `test_fetches_spec_from_url`, `test_endpoints_stored_on_module`, `test_findings_added_to_module` |

---

## Running Tests

```bash
# Run all 284 tests
pytest

# Run a single module's tests
pytest tests/test_sneakygits/
pytest tests/test_bosskey/
pytest tests/test_waaaghlogic/
pytest tests/test_grotassault/
pytest tests/test_redteef/
pytest tests/test_waaaghgate/
pytest tests/test_openkrump/
```
