# Contributing to GateKrumpa

Thanks for your interest in contributing! This document covers the guidelines
and workflow for the project.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/SnikSec/GateKrumpa.git
cd GateKrumpa

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux

# Install in editable mode with all dev dependencies
pip install -e ".[dev,yaml,mcp]"

# Optional: install cloud/AI/repo attack extras
pip install -e ".[cloud,ai,repo,art]"
```

## Development Workflow

1. **Branch from `dev`** — all work targets the `dev` branch.
2. **Write tests first** (or alongside) — we maintain 1118+ tests.
3. **Run the checks before pushing:**

```bash
# Type checking (must be 0 errors, 0 warnings)
python -m pyright src/

# Tests (must all pass)
python -m pytest tests/ -q
```

## Project Structure

```
src/krumpa/
├── core/              # Shared primitives (BaseModule, HttpClient, ScanContext,
│                      #   TargetType, AttackChain, HVTScorer, ai_orchestrator)
├── mcp/               # MCP server — 11 tools for AI agents
├── sneakygits/        # Module 1  — Recon, fingerprinting, passive recon
├── bosskey/           # Module 2  — Auth, session, cloud identity
├── waaaghlogic/       # Module 3  — Business logic testing
├── grotassault/       # Module 4  — Mutation fuzzing (46 SSRF payloads)
├── redteef/           # Module 5  — Exploit confirmation (1CV paths)
├── waaaghgate/        # Module 6  — CI/CD gate, blast radius, verification
├── openkrump/         # Module 7  — API-first (OpenAPI/Swagger/gRPC)
├── cloudstrike/       # Module 8  — AWS attack surface (aws:// targets)
├── aifuzz/            # Module 9  — AI/LLM attack surface
├── modelhunt/         # Module 10 — Model extraction, vector DB, supply chain
└── reposcout/         # Module 11 — GitHub/GitLab targeting (github:// targets)
```

**Pipeline order:**
`sneakygits → openkrump → cloudstrike → reposcout → bosskey → waaaghlogic → aifuzz → grotassault → redteef → modelhunt → waaaghgate`

## Adding a New Module

Every module must:

1. Subclass `BaseModule` from `krumpa.core`.
2. Declare `name`, `description`, and `dependencies` class attributes.
3. Implement `async run(ctx: ScanContext) -> List[Finding]`.
4. Register in `_MODULE_REGISTRY` and `_DEFAULT_ORDER` in `__main__.py`.
5. Add to `WaaaghGateModule.dependencies` if it should block the gate.

For non-HTTP targets (cloud, repo), use the pseudo-URL scheme convention:
`aws://`, `github://`, `gitlab://` — modules filter by `target.target_type`.

## Adding a New Sub-Component

Every sub-component that uses HTTP should:

1. Accept `http_client: Optional[HttpClient] = None` in `__init__`.
2. Inherit from `HttpClientMixin` (from `krumpa.core.http_client`).
3. Store `self._client = http_client` and `self._owns_client = http_client is None`.
4. The parent `module.py` wires the shared client via `component.set_client(ctx.http_client)` in `setup()`.

Components that use cloud SDKs (`boto3`, `PyGithub`, `python-gitlab`) instead:
- Accept a `session` (boto3 Session) or `token` (API token) in `__init__`.
- Check for optional dependencies with a try/except at the top of `run()`.
- Log a `logger.warning()` and return `[]` if the library is not installed.

## Coding Standards

- **Python 3.11+** — use modern syntax (`match`, `|` unions, etc.).
- **Type hints everywhere** — pyright `standard` mode, 0 warnings.
- **Async-first** — all HTTP-touching code should be `async`.
- **Dataclasses** for value objects, not dicts.
- **Imports** — absolute imports from `krumpa.*`, no relative imports.
- **Evidence redaction** — never store actual secret values in `Finding.evidence`. Store path, line number, and a truncated/redacted preview only.
- **Scope safety** — all new HTTP modules must respect `HttpClient`'s built-in SSRF protection unless `allow_private_networks=True` is explicitly required and documented.

## Commit Messages

Use conventional-style prefixes:

- `feat:` — new feature or capability
- `fix:` — bug fix
- `refactor:` — code restructuring without behaviour change
- `tech-debt:` — cleanup, warning fixes, import tidying
- `docs:` — documentation only
- `test:` — test additions or changes

## Reporting Issues

Open a GitHub issue with:

Thanks for your interest in contributing! This document covers the guidelines
and workflow for the project.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/SnikSec/GateKrumpa.git
cd GateKrumpa

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Development Workflow

1. **Branch from `dev`** — all work targets the `dev` branch.
2. **Write tests first** (or alongside) — we maintain 692+ tests.
3. **Run the checks before pushing:**

```bash
# Type checking (must be 0 errors, 0 warnings)
python -m pyright src/

# Tests (must all pass)
python -m pytest tests/ -q
```

## Project Structure

```
src/krumpa/
├── core/           # Shared primitives (BaseModule, HttpClient, ScanContext, etc.)
├── sneakygits/     # Recon module
├── bosskey/        # Auth modelling module
├── waaaghlogic/    # Business logic testing module
├── grotassault/    # Mutation fuzzing module
├── redteef/        # Exploit confirmation module
├── waaaghgate/     # CI/CD integration module
└── openkrump/      # API-first testing module
```

## Adding a New Sub-Component

Every sub-component that uses HTTP should:

1. Accept `http_client: Optional[HttpClient] = None` in `__init__`.
2. Inherit from `HttpClientMixin` (from `krumpa.core.http_client`).
3. Store `self._client = http_client` and `self._owns_client = http_client is None`.
4. The parent `module.py` wires the shared client via `component.set_client(ctx.http_client)` in `setup()`.

## Coding Standards

- **Python 3.11+** — use modern syntax (`match`, `|` unions, etc.).
- **Type hints everywhere** — pyright `standard` mode, 0 warnings.
- **Async-first** — all HTTP-touching code should be `async`.
- **Dataclasses** for value objects, not dicts.
- **Imports** — absolute imports from `krumpa.*`, no relative imports.

## Commit Messages

Use conventional-style prefixes:

- `feat:` — new feature or capability
- `fix:` — bug fix
- `refactor:` — code restructuring without behaviour change
- `tech-debt:` — cleanup, warning fixes, import tidying
- `docs:` — documentation only
- `test:` — test additions or changes

## Reporting Issues

Open a GitHub issue with:
- Steps to reproduce
- Expected vs. actual behaviour
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the
MIT License (see [LICENSE](LICENSE)).
