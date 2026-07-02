# GateKrumpa — Agent Instructions

Modular dynamic attack simulation platform for web apps, cloud environments,
AI/LLM systems, and source repositories. See [README.md](../README.md) for full
capability overview. See [TODO.md](../TODO.md) for the working task list.

---

## Architecture

```
src/krumpa/
├── core/           # Shared primitives — BaseModule, HttpClient, ScanContext,
│                   #   TargetType, AttackChain, HVTScorer, ai_orchestrator
├── mcp/            # FastMCP server — 13 tools
├── sneakygits/     # Module 1  — Recon & fingerprinting
├── bosskey/        # Module 2  — Auth, session, cloud identity
├── waaaghlogic/    # Module 3  — Business logic testing
├── grotassault/    # Module 4  — Mutation fuzzing
├── redteef/        # Module 5  — Exploit confirmation
├── waaaghgate/     # Module 6  — CI/CD gate, blast radius, verification
├── openkrump/      # Module 7  — API-first (OpenAPI/Swagger/gRPC)
├── cloudstrike/    # Module 8  — AWS attack surface (aws:// targets)
├── aifuzz/         # Module 9  — AI/LLM attack surface (14 components)
├── modelhunt/      # Module 10 — Model extraction, vector DB, supply chain
└── reposcout/      # Module 11 — GitHub/GitLab (github:// / gitlab:// targets)
```

**Pipeline order:**
`sneakygits → openkrump → cloudstrike → reposcout → bosskey → waaaghlogic → aifuzz → grotassault → redteef → modelhunt → waaaghgate`

**Target URL schemes** — non-HTTP targets use pseudo-URL schemes on `Target.url`:

| Scheme | Module | Notes |
|--------|--------|-------|
| `https?://` | any web module | default |
| `aws://REGION` | cloudstrike | uses boto3 directly, never HttpClient |
| `github://ORG/REPO` | reposcout | uses PyGithub |
| `gitlab://HOST/GROUP/REPO` | reposcout | uses python-gitlab |

---

## Build & Test

```bash
# Install
pip install -e ".[dev,yaml,mcp]"

# Run all tests (must all pass before committing)
pytest tests/ -q

# Lint (must be clean before committing)
ruff check src/ tests/

# Optional extras
pip install -e ".[cloud,ai,repo,art,vision]"
```

**Current counts** (update these when they change):
- Tests: **1200 passing, 1 skipped**
- MCP tools: **13 default** (14 with a custom tool)
- Modules: **11**
- Version: **0.2.0**

---

## Document Maintenance Rules

When these events occur, update the documents listed.

### Adding or removing a module
1. `src/krumpa/__main__.py` — `_MODULE_REGISTRY` + `_DEFAULT_ORDER`
2. `src/krumpa/waaaghgate/module.py` — `WaaaghGateModule.dependencies`
3. `README.md` — module table, architecture tree, pipeline order string
4. `CONTRIBUTING.md` — project structure tree, pipeline order
5. `TODO.md` — mark item complete or add new task
6. `CHANGELOG.md` — add entry under `[Unreleased]`

### Adding or removing an MCP tool
1. `src/krumpa/mcp/tools.py` — register tool in `register_default_tools()`
2. `tests/test_mcp/test_server.py` — update **three** hardcoded counts:
   - `test_default_tools_registered` → expected set of tool names
   - `test_all_seven_tools` → `assert len(names) == N`
   - `test_register_idempotent` → `assert len(names) == N`
   - `test_custom_tool_alongside` → `assert len(names) == N+1`
3. `README.md` — MCP tools table
4. The "Current counts" section above

### Bumping the version
All five locations must be updated together:
1. `pyproject.toml` — `version = "X.Y.Z"`
2. `src/krumpa/__main__.py` — `@click.version_option("X.Y.Z", ...)`
3. `src/krumpa/core/reporting.py` — `"version": "X.Y.Z"` in `to_sarif()`
4. `README.md` — header `**Version:** X.Y.Z`
5. `CHANGELOG.md` — promote `[Unreleased]` to `[X.Y.Z] — YYYY-MM-DD`

### After adding new tests
1. `README.md` — `**N tests passing**` in header + Running Tests table
2. `CONTRIBUTING.md` — `N+` tests count
3. This file — "Current counts" above

### After closing a TODO.md phase
1. `TODO.md` — mark all items `[x]`; add Phase N+1 stubs
2. `CHANGELOG.md` — add `[Unreleased]` entry for next cycle

---

## Module Creation Checklist

When creating a new `BaseModule` subclass:

1. **Implement** `name`, `description`, `dependencies` class attributes and `async run(ctx) → List[Finding]`
2. **URL scheme check** — for non-HTTP targets, filter by `target.target_type` in `run()` before doing any work; return `[]` immediately if no matching targets
3. **Optional library guard** — wrap SDK imports (`boto3`, `PyGithub`, etc.) in `try/except ImportError`; log a `logger.warning()` and return `[]`
4. **Register** the module in `__main__.py` (`_MODULE_REGISTRY`, `_DEFAULT_ORDER`) and in `waaaghgate/module.py` dependencies
5. **Tests** — create `tests/test_<module>/` with `__init__.py`, `test_module.py`, and component-level tests; use mocked HTTP (never real network); use `moto` for AWS; never real API keys
6. **Update docs** — follow the "Adding a module" rule above

---

## Coding Conventions

- **Python 3.11+** — use modern syntax; no `from __future__ import annotations` needed in new files but keep it in existing ones
- **Async-first** — all HTTP and SDK calls must be `async`
- **Ruff** — keep `ruff check src/ tests/` at 0 errors; do not introduce `F401`, `F841`, `E701`, `E731` violations
- **Evidence redaction** — never store raw secret values in `Finding.evidence`; store path + line number + redacted preview only
- **SSRF protection** — `HttpClient` blocks private IPs by default; only set `allow_private_networks=True` when explicitly required and documented
- **Dataclasses** for value objects, not plain dicts
- **No `type: ignore` spam** — only use where the library genuinely has no stubs

---

## Git Workflow

- All work on `dev` branch
- Merge to `main` only when tests and lint are clean
- Commit message prefix: `feat:`, `fix:`, `refactor:`, `tech-debt:`, `docs:`, `test:`
- Before merging: run `pytest tests/ -q` + `ruff check src/ tests/`
