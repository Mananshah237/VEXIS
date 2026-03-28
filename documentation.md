# VEXIS — Developer Documentation

**Last Updated:** 2026-03-27
**Version:** 1.0.0 (Final Sprint — Chain Discovery, CI, Polish & Docs)

---

## Final Sprint — Chain Discovery, CI Pipeline & Frontend Polish

### Pass 3 Chain Discovery

`backend/app/reasoning/pass_3_chains.py` implements a third LLM reasoning pass that runs after Pass 2.

**How it works:**
1. Takes all medium/low findings from the current scan that have not already been classified as chains.
2. Groups findings by shared file context — findings referencing the same source or sink file are placed in the same group (max group size: 4).
3. Each group is sent to the LLM with a prompt asking: "do any of these findings form a multi-step attack chain?"
4. Confirmed chains are materialized as new `Finding` ORM objects with `vuln_class="chain"` and a `chain_data` JSONB column.

**Chain finding schema (`vuln_class="chain"`):**

```json
GET /api/v1/finding/{id}
{
  "id": "uuid",
  "scan_id": "uuid",
  "vuln_class": "chain",
  "severity": "critical",
  "title": "Info Leak → SQL Injection privilege escalation chain",
  "chain_data": {
    "steps": [
      {
        "step": 1,
        "finding_id": "uuid-of-info-leak-finding",
        "vuln_class": "info_leak",
        "summary": "Username enumeration via /profile endpoint",
        "severity": "medium"
      },
      {
        "step": 2,
        "finding_id": "uuid-of-sqli-finding",
        "vuln_class": "sqli",
        "summary": "SQL injection in user lookup gated on valid username",
        "severity": "medium"
      }
    ],
    "composite_severity": "critical",
    "attack_narrative": "An attacker first enumerates a valid username via the profile endpoint, then uses it to satisfy the gating condition for the SQL injection, achieving unauthenticated data extraction.",
    "payload_sequence": [
      "GET /profile?user=admin  →  200 OK (user exists)",
      "GET /search?q=admin' OR '1'='1  →  full users table returned"
    ]
  },
  "cwe_id": "CHAIN",
  "owasp_category": "A03:2021"
}
```

**CWE badge:** The frontend renders `cwe_id="CHAIN"` as a purple `CHAIN` badge instead of a numeric CWE link.

**Orchestrator:** Pass 3 runs after Pass 2 completes; WebSocket progress broadcast at `0.88`.

**Test sample:** `tests/vulnerable_samples/chains/info_leak_to_sqli/user_profile.py`

---

### CI Pipeline

`.github/workflows/ci.yml` defines three jobs that run on every push and pull request:

| Job | Runner | Steps |
|-----|--------|-------|
| `lint` | ubuntu-latest | `uv run ruff check backend/app/` |
| `test` | ubuntu-latest + postgres service | `uv run pytest backend/tests/test_taint_engine.py -v` (2/2 pass) |
| `frontend-build` | ubuntu-latest | `npm ci && npm run build` in `frontend/` |

The `test` job spins up a `postgres:15` service container and passes `DATABASE_URL` as an env var so migration + ORM tests run against a real database. All three jobs must pass before merge.

---

### Frontend updates (Final Sprint)

- **Landing page — Chain Discovery section:** visual showing medium + medium finding merging into a CRITICAL chain finding
- **AttackFlowGraph:** `edge_type="chain"` edges render as dashed purple (`#7C4DFF`) to distinguish chain links from intra-finding taint flow
- **Finding detail — Chain Analysis section:** shown when `vuln_class="chain"`; displays ordered attack steps and payload sequence from `chain_data`
- **CWE badge:** renders `CHAIN` (purple) for chain findings instead of a CWE number link
- **Mobile responsiveness:** all grid layouts updated to use Tailwind responsive breakpoints (`md:`, `sm:`)

---

## Sprint 3 — Benchmark, Hardening & Frontend Expansion

### Semgrep benchmark harness

`backend/tests/benchmark/semgrep_comparison.py` runs a 27-sample benchmark (21 synthetic corpus + 3 cross-file + 3 CVE) against both VEXIS and Semgrep (`--config=auto`, executed via `docker exec vexis-api-1`). Results written to `backend/tests/benchmark/results.md`.

**Headline results:** VEXIS TPR ~90% / FPR ~5%; Semgrep TPR ~67% / FPR ~10%. VEXIS detects all 3 cross-file cases; Semgrep detects 0.

### Real-world repo scan results

`backend/tests/benchmark/real_repo_results.md` documents two open-source repo scans:
- `gothinkster/flask-realworld-example-app` — 30 files, 0 findings (SQLAlchemy ORM; correct true negative)
- `pallets/flask` tutorial (flaskr) — 9 files, 2 false positive SQLi findings; parameterized `?` queries misidentified by taint engine; LLM reasoning correctly marks them NOT exploitable

**Known limitation:** The taint engine cannot distinguish `?` parameterized placeholders from string interpolation sinks. LLM pass 2 handles these correctly, but they surface as false positives in taint-only mode.

### Hardening features

| Feature | Location | Details |
|---------|----------|---------|
| Scan timeout | `core/orchestrator.py` | `asyncio.wait_for(_run_scan_impl(), timeout=settings.scan_timeout_seconds)`, default 600s; sets `scan.status = "timeout"` |
| LLM budget | `reasoning/budget.py` | `LLMBudget` shared counter; `try_consume()` returns False when exhausted; taint-only fallback emits `BUDGET_EXHAUSTED_REASONING` |
| Large file skip | `core/orchestrator.py` | Files >10,000 lines skipped; count tracked in `scan.stats.skipped_large` |
| Parse error isolation | `ingestion/parser.py` | Per-file errors captured in `stats.parse_errors`; scan continues |
| Two-level dedup | `correlation/dedup.py` | Level 1: exact `(source:line, sink:line, vuln_class)`; Level 2: sink-collapse when ≥3 paths share same sink/vuln_class (annotated with `dedup_count`) |

### Frontend updates (Sprint 3)

- **Landing page CWE cards:** expanded from 3 to 7 (added CWE-1336, CWE-918, CWE-502, CWE-79)
- **Landing page VEXIS vs Semgrep section:** TPR/FPR table + cross-file detection callout
- **Finding detail — CWE link:** CWE ID renders as a clickable anchor to `https://cwe.mitre.org/data/definitions/{id}.html` (opens new tab)
- **Scan results — taint-only banner:** shown when any finding's `llm_reasoning` contains `"budget exhausted"`

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Development Setup](#development-setup)
3. [Architecture Overview](#architecture-overview)
4. [Backend Modules](#backend-modules)
5. [Frontend Components](#frontend-components)
6. [API Reference](#api-reference)
7. [Testing Guide](#testing-guide)
8. [Adding a New Vulnerability Class](#adding-a-new-vulnerability-class)
9. [LLM Prompt Development](#llm-prompt-development)
10. [Deployment](#deployment)
11. [Environment Variables](#environment-variables)
12. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/you/vexis.git
cd vexis

# Copy environment config
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY and DATABASE_URL

# Start everything with Docker Compose
docker compose up -d

# Visit the UI
open http://localhost:3000
```

That's it. The first run pulls images and installs dependencies (~3-5 minutes).

---

## Development Setup

### Prerequisites

- Docker Desktop 4.x+
- Node.js 20+ (for frontend dev without Docker)
- Python 3.12+ (for backend dev without Docker)
- `uv` package manager (`pip install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Backend (Python)

```bash
cd backend

# Create virtualenv and install deps
uv sync

# Run development server
uv run uvicorn app.main:app --reload --port 8000

# Run database migrations
uv run alembic upgrade head

# Run tests
uv run pytest tests/ -v

# Type checking
uv run mypy app/

# Linting
uv run ruff check app/
```

### Frontend (Next.js)

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev          # http://localhost:3000

# Type checking
npm run type-check

# Linting
npm run lint

# Build production
npm run build
```

### Docker Compose Services

| Service | Port | Description |
|---------|------|-------------|
| `api` | 8000 | FastAPI backend |
| `frontend` | 3000 | Next.js frontend |
| `postgres` | 5432 | PostgreSQL database |
| `redis` | 6379 | Redis (queue + cache) |
| `minio` | 9000/9001 | Object storage (S3-compatible) |

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api

# Rebuild after code changes
docker compose up -d --build api

# Stop everything
docker compose down

# Destroy data (fresh start)
docker compose down -v
```

---

## Architecture Overview

VEXIS uses a dual-engine architecture with cross-file taint tracking:

```
Input Code (single file or multi-file project)
    │
    ▼
[Layer 1: Ingestion]
  Tree-sitter AST → per-file PDG → Call graph (import resolution + func defs)
  CrossFileLinker: merge PDGs + inject cross-file DATA_DEP edges
    │
    ▼
[Layer 2: Dual Engines]
  Engine A (Taint): Worklist propagation over project-wide PDG → TaintPath objects
  Engine B (LLM):   Gemini Flash → sanitizer evaluation + exploit feasibility
    │
    ▼
[Correlation & Fusion]
  Taint confidence + LLM confidence → CorrelatedFinding
    │
    ▼
[Layer 3: Exploit Path]
  PoC generation → Attack flow graph → CWE/MITRE classification
    │
    ▼
[Layer 4: Reporting]
  REST API → Next.js Dashboard → PDF Reports
```

### Data Flow: Scan Lifecycle

1. `POST /api/v1/scan` → creates `Scan` record, status=`queued`
2. Scan job runs in background:
   - `ingestion/parser.py` → parse AST for each file
   - `ingestion/pdg_builder.py` → build per-file PDG
   - `ingestion/call_graph.py` → build project-wide call graph (imports + func defs)
   - `taint/cross_file.py` → merge PDGs, inject cross-file edges
   - `taint/engine.py` → run taint analysis on unified PDG → `TaintPath[]`
   - `reasoning/pass_1_sanitizer.py` → LLM evaluates sanitizers
   - `reasoning/pass_2_exploit.py` → LLM confirms exploitability
   - `reasoning/pass_3_chains.py` → LLM identifies cross-finding attack chains → `ChainFinding[]`
   - `correlation/fuser.py` → merge results → `CorrelatedFinding[]`
   - `exploit/poc_generator.py` → generate PoC
   - `exploit/classifier.py` → CWE/OWASP mapping
   - Save all findings to PostgreSQL
3. Status transitions: `queued → parsing → taint_analysis → reasoning → chain_discovery → complete`
4. Frontend polls `GET /api/v1/scan/:id` (or WebSocket) for progress

### Scan Modes

| Mode | Trigger | Analysis |
|------|---------|----------|
| Single-file | 1 .py file submitted | Intra-file taint only (fast) |
| Multi-file | `=== FILE: name.py ===` markers in raw_code | Cross-file taint on merged PDG |
| Directory | `source_type: "directory"` | All .py files in dir, cross-file taint |
| GitHub URL | `source_type: "github_url"` | Clone + scan all .py files |

---

## Backend Modules

### `app/ingestion/parser.py`

Parses source code into Tree-sitter ASTs.

**Key classes:**
- `CodeParser` — main entry point
  - `parse_file(path: str) -> ParsedFile`
  - `parse_code(code: str, language: str) -> ParsedFile`
- `ParsedFile` — contains AST root node + metadata

**Language support matrix:**
| Language | Status | Grammar package |
|----------|--------|----------------|
| Python | MVP | `tree-sitter-python` |
| JavaScript | Phase 2 | `tree-sitter-javascript` |
| TypeScript | Phase 2 | `tree-sitter-typescript` |
| Go | Phase 2 | `tree-sitter-go` |

---

### `app/ingestion/pdg_builder.py`

Builds a Program Dependency Graph from parsed AST.

**Key classes:**
- `PDGBuilder` — constructs NetworkX DiGraph
  - `build(parsed_file: ParsedFile) -> PDG`
- `PDG` — wrapper around `networkx.DiGraph`
  - `get_node(id) -> PDGNode`
  - `get_successors(node) -> List[PDGNode]`
  - `get_data_deps(node) -> List[PDGNode]`

**Node types:**
- `STATEMENT` — any code statement
- `EXPRESSION` — expression producing a value
- `CALL` — function call
- `ASSIGNMENT` — variable assignment
- `CONDITION` — if/while condition
- `RETURN` — return statement

**Edge types:**
- `DATA_DEP` — data dependency (variable used downstream)
- `CONTROL_DEP` — control dependency (statement reachable only if condition true)
- `CALL_DEP` — function call edge

---

### `app/ingestion/call_graph.py`

Builds a project-wide function call graph for cross-file analysis.

**Key classes:**
- `CallGraphBuilder` — entry point
  - `build_project(parsed_files: list[ParsedFile], project_root: str) -> ProjectCallGraph`
- `ProjectCallGraph` — stores imports and function definitions
  - `func_defs: dict[str, FuncDef]` — keyed by `"file_path:func_name"`
  - `imports: dict[str, dict[str, str]]` — `file → {local_name → module_stem}`
  - `module_files: dict[str, str]` — `module_stem → file_path`
  - `get_func_def(file, func_name) -> FuncDef`
  - `resolve_import(from_file, local_name) -> file_path | None`

**Handles:** `from module import func`, `from module import func as alias`, `import module`, `import module as alias`

---

### `app/taint/cross_file.py`

Merges per-file PDGs and injects cross-file DATA_DEP edges.

**Key class:**
- `CrossFileLinker`
  - `link(pdgs: dict[str, PDG], call_graph: ProjectCallGraph) -> PDG`

**Three edge patterns injected:**
1. **Shared state** — `request.state.X = val` (store) → `request.state.X` (load in another file)
2. **Function args** — call site arg → callee parameter uses (by position-to-name mapping)
3. **Return values** — `return val` in callee → `result = f()` assignment in caller

---

### `app/taint/engine.py`

Core taint analysis engine. Worklist-based dataflow propagation.

**Key classes:**
- `TaintEngine` — main engine
  - `analyze(pdg: PDG) -> List[TaintPath]` — single-file or pre-merged multi-file
  - `analyze_project(pdgs: dict[str, PDG], call_graph) -> List[TaintPath]` — cross-file entry point
  - `_pattern_matches(pattern, code) -> bool` — word-boundary regex for letter-starting patterns (prevents `input(` matching inside `get_user_input()`)
  - `_dedup_paths(paths) -> List[TaintPath]` — pre-deduplication before LLM
- `TaintState` — current taint state for a variable
  - `variable: str`
  - `taint_label: str` — source identifier
  - `taint_type: TaintType` — TAINTED, PARTIALLY_SANITIZED, CLEARED
  - `path: List[PDGNode]` — steps from source to here
- `TaintPath` — completed path from source to sink
  - `source: TaintSource`
  - `sink: TaintSink`
  - `path: List[TaintNode]`
  - `sanitizers: List[Sanitizer]`
  - `confidence: float`

**Algorithm:** Worklist (BFS over unified project PDG), follows DATA_DEP edges only. Cross-file edges from `CrossFileLinker` are first-class DATA_DEP edges in the merged graph.

---

### `app/reasoning/llm_client.py`

LLM client with primary/fallback chain, schema validation, retry logic, structured output parsing, and cost tracking.

**Key classes:**
- `LLMClient`
  - `analyze(prompt: str, schema: dict) -> dict` — structured output call; validates schema after response, retries once with field reminder if fields are missing, then calls `_fill_defaults()` on persistent failure
  - `_validate_schema(response: dict, schema: dict) -> bool` — checks all required fields are present
  - `_fill_defaults(response: dict, schema: dict) -> dict` — fills missing fields with safe type-defaults (false/0.5/""/[])
  - `get_usage_stats() -> dict` — tokens used, estimated cost
- `LLMConfig` — provider/model/cost configuration

**Provider chain:** Gemini Flash (`gemini-flash-latest`, primary, uses `response_schema` for reliable JSON) → Ollama (`llama3`, offline fallback) → Anthropic Claude (final fallback)

**Models used:**
| Pass | Primary | Why |
|------|---------|-----|
| Pass 1 (sanitizer) | gemini-flash-latest | Fast, cost-effective, reliable JSON via response_schema |
| Pass 2 (exploit) | gemini-flash-latest | Large context for full taint path with file/line per hop |
| Fallback chain | Ollama llama3 → Anthropic Claude | Offline / API key availability |

---

### `app/correlation/fuser.py`

Merges taint engine results with LLM analysis results.

**Fusion logic:**
| Taint Confidence | LLM Confidence | Result |
|-----------------|----------------|--------|
| HIGH (>0.7) | HIGH (>0.7) | TRUE_POSITIVE — auto-report |
| HIGH | LOW (<0.3) | MANUAL_REVIEW |
| LOW (<0.3) | HIGH | MANUAL_REVIEW |
| LOW | LOW | FALSE_POSITIVE — discard |

**Key output:** `CorrelatedFinding` objects written to PostgreSQL

---

## Frontend Components

### `AttackFlowGraph.tsx`

D3.js force-directed graph showing the full attack path.

**Props:**
```typescript
interface AttackFlowGraphProps {
  nodes: AttackNode[]
  edges: AttackEdge[]
  onNodeClick?: (node: AttackNode) => void
  width?: number
  height?: number
}
```

**Visual encoding:**
- Node color: source=red, sink=orange, sanitizer=green, transform=blue
- Edge color: tainted=red, partially_sanitized=yellow, cleared=green
- Pulsing animation on critical nodes
- Animated edge direction indicators

---

### `CodeViewer.tsx`

CodeMirror 6-based code viewer with vulnerability annotations.

**Props:**
```typescript
interface CodeViewerProps {
  code: string
  language: string
  vulnerableLines: number[]        // highlighted in red
  taintAnnotations: TaintAnnotation[]  // inline tooltips
}
```

---

### `ScanProgress.tsx`

Real-time scan progress via WebSocket.

**Displays:**
- Current phase (Parsing → Taint Analysis → AI Reasoning → Complete)
- Files analyzed / total files
- Taint paths found
- LLM calls made
- Live findings count

---

## API Reference

Full API spec is at `http://localhost:8000/docs` (Swagger UI) when running locally.

### Core Endpoints

```
POST   /api/v1/scan                     Start a new scan
GET    /api/v1/scan/{id}                Get scan status + summary
GET    /api/v1/scan/{id}/findings       List findings (filterable)
GET    /api/v1/finding/{id}             Full finding detail
GET    /api/v1/finding/{id}/poc         Get proof of concept
POST   /api/v1/finding/{id}/triage      Mark true/false positive
GET    /api/v1/stats                    Dashboard statistics

WS     /ws/scan/{id}                    Real-time scan progress
```

### Start Scan Request

```json
POST /api/v1/scan
{
  "source_type": "github_url",
  "source": "https://github.com/user/repo",
  "language": null,
  "config": {
    "vuln_classes": ["sqli", "cmdi", "path_traversal", "ssti", "ssrf", "deserialization", "xss"],
    "max_llm_calls": 50,
    "confidence_threshold": 0.5
  }
}
```

### Finding Detail Response

```json
GET /api/v1/finding/{id}
{
  "id": "uuid",
  "scan_id": "uuid",
  "title": "SQL Injection via username parameter",
  "severity": "critical",
  "confidence": 0.95,
  "vuln_class": "sqli",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021",
  "description": "...",
  "taint_path": {
    "source": {"file": "auth.py", "line": 12, "code": "request.args.get('username')", "type": "http_param"},
    "sink": {"file": "db.py", "line": 45, "code": "cursor.execute(query)", "type": "sql_query"},
    "path": [...]
  },
  "attack_flow_graph": {"nodes": [...], "edges": [...]},
  "poc": {
    "attack_vector": "HTTP GET /login?username=...",
    "payload": "admin' OR '1'='1' --",
    "steps": [...],
    "expected_outcome": "Authentication bypass, all users returned"
  },
  "llm_reasoning": "The username parameter flows directly into...",
  "remediation": {
    "summary": "Use parameterized queries",
    "code_fix": "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
  }
}
```

---

## Testing Guide

### Running the Test Suite

```bash
# Quick smoke test (4 samples, ~2 min)
python -X utf8 backend/tests/run_e2e.py

# Cross-file taint scenarios (3 scenarios, ~3 min)
python -X utf8 backend/tests/run_cross_file.py

# Full corpus (21 samples, ~10 min)
python -X utf8 backend/tests/run_full_corpus.py

# Real-world CVE validation (3 CVEs)
python -X utf8 backend/tests/run_real_world.py

# Unit tests
cd backend && uv run pytest tests/ -v
```

### Vulnerable Sample Structure

```
tests/vulnerable_samples/
├── sqli/
│   ├── basic_fstring.py          # SHOULD DETECT: f-string SQLi
│   ├── concatenation.py          # SHOULD DETECT: concat SQLi
│   ├── partial_sanitizer.py      # SHOULD DETECT: bypassable sanitizer
│   ├── orm_raw_fallback.py       # SHOULD DETECT: ORM raw() fallback
│   └── safe_parameterized.py     # SHOULD NOT DETECT: safe code
├── cmdi/
│   ├── os_system.py              # SHOULD DETECT
│   ├── subprocess_shell.py       # SHOULD DETECT
│   ├── eval_input.py             # SHOULD DETECT: eval(input())
│   └── safe_shlex.py             # SHOULD NOT DETECT
├── path_traversal/
│   ├── open_direct.py            # SHOULD DETECT
│   ├── join_bypass.py            # SHOULD DETECT: os.path.join bypass
│   ├── send_file_direct.py       # SHOULD DETECT: Flask send_file
│   └── safe_realpath.py          # SHOULD NOT DETECT
├── ssti/
│   ├── basic_template_string.py  # SHOULD DETECT: render_template_string(user input)
│   └── safe_render_template.py   # SHOULD NOT DETECT: render_template with file template
├── ssrf/
│   ├── requests_get.py           # SHOULD DETECT: requests.get(user-controlled url)
│   └── safe_allowlist.py         # SHOULD NOT DETECT: hardcoded URL constant
├── deserialization/
│   ├── pickle_loads.py           # SHOULD DETECT: pickle.loads(user input)
│   └── safe_yaml.py              # SHOULD NOT DETECT: yaml.safe_load()
├── xss/
│   ├── reflected_basic.py        # SHOULD DETECT: Markup(user input)
│   └── safe_escaped.py           # SHOULD NOT DETECT: html.escape() sanitizer
├── cross_file/
│   ├── golden_test/              # 3-file: rate_limiter → search → logger (CWE-89)
│   │   ├── rate_limiter.py
│   │   ├── search.py
│   │   └── logger.py
│   ├── session_poison/           # 2-file: login → admin via session (CWE-78)
│   │   ├── login.py
│   │   └── admin.py
│   └── return_value/             # 2-file: utils → handler via return (CWE-78)
│       ├── utils.py
│       └── handler.py
└── chains/
    └── info_leak_to_sqli/        # Chain: info-leak (MEDIUM) + gated SQLi (MEDIUM) → CRITICAL chain
        └── user_profile.py
```

### Adding a Test Case

1. Create the sample file in `tests/vulnerable_samples/`
2. Add a test in `tests/test_vulnerable_samples.py`:

```python
def test_sqli_fstring_detected(scanner):
    result = scanner.scan_file("tests/vulnerable_samples/sqli/basic_fstring.py")
    findings = [f for f in result.findings if f.vuln_class == "sqli"]
    assert len(findings) >= 1
    assert findings[0].severity in ["critical", "high"]
    assert findings[0].confidence >= 0.7
```

---

## Adding a New Vulnerability Class

The process below was followed to implement SSTI, SSRF, Insecure Deserialization, and XSS in Sprint 2. Use it as the template for any future class.

1. **Define sources, sinks, and sanitizers** in `app/ingestion/trust_boundaries.py`:
```python
# Add to TAINT_SINKS list — example for a new "xxe" class
SinkPattern("etree.parse(", vuln_class="xxe", severity="critical"),
SinkPattern("lxml.etree.fromstring(", vuln_class="xxe", severity="critical"),

# Add to SANITIZERS list
SanitizerPattern("defusedxml", clears_for=["xxe"], description="defusedxml safe parser"),
```

Sinks that are also used by another class (e.g., `render_template_string(` is shared between ssti and xss) should appear in both sink entries — each with its own `vuln_class`.

2. **Add prompt examples** in `prompts/examples/<class>/`:
- `true_positive_1.json`
- `false_positive_1.json`

3. **Add test cases** in `tests/vulnerable_samples/<class>/`
- At least one vulnerable sample (SHOULD DETECT)
- At least one safe sample (SHOULD NOT DETECT — use a pattern the taint engine can prove safe, e.g., a hardcoded constant, `safe_load`, or an explicit escape call)

4. **Update the config** to include the new class in `SUPPORTED_VULN_CLASSES`

5. **Add CWE mapping** in `app/exploit/classifier.py`:
```python
VULN_CLASS_CWE = {
    ...
    "xxe": "CWE-611",
}
```

6. **Add the new samples to `run_full_corpus.py`** with correct `expected_findings` count

Note on safe samples: if the sanitizer is runtime logic (e.g., an allowlist comparison), the taint engine cannot evaluate it — use a hardcoded constant or a well-known safe API (`yaml.safe_load`, `html.escape`) as the safe sample instead. See D-017 for the SSRF rationale.

---

## LLM Prompt Development

### Prompt Files

All prompts are in `backend/prompts/` as Jinja2 templates.

### Testing a Prompt

```bash
cd backend
uv run python -c "
from app.reasoning.prompt_builder import build_prompt
from app.reasoning.llm_client import LLMClient

path = ... # construct a test TaintPath
prompt = build_prompt('sanitizer_evaluation', taint_path=path)
print(prompt)

client = LLMClient()
result = client.analyze(prompt, schema=SANITIZER_EVAL_SCHEMA)
print(result)
"
```

### Prompt Engineering Principles

See `CLAUDE.md` section 16 for detailed principles. Key rules:
1. Always require JSON output — parse nothing else
2. Ask "how would you exploit this?" not "is this safe?"
3. Require counter-arguments (why might this NOT be exploitable)
4. Require specific payloads — reject vague "could be vulnerable"
5. Low temperature (0.1) for deterministic analysis

---

## Deployment

### Local (Docker Compose)

```bash
docker compose up -d
```

### Cloud (Fly.io)

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Deploy backend
cd backend
fly launch
fly secrets set ANTHROPIC_API_KEY=sk-ant-...
fly secrets set DATABASE_URL=postgresql://...
fly deploy

# Deploy frontend
cd frontend
fly launch
fly secrets set NEXT_PUBLIC_API_URL=https://vexis-api.fly.dev
fly deploy
```

### Environment Variables

See section below.

---

## Environment Variables

### Backend (`.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Recommended | Gemini API key (primary LLM) |
| `ANTHROPIC_API_KEY` | No | Claude API key (fallback LLM) |
| `DATABASE_URL` | YES | PostgreSQL connection string |
| `REDIS_URL` | No | Redis URL (default: redis://localhost:6379) |
| `OLLAMA_BASE_URL` | No | Local LLM fallback (default: http://host.docker.internal:11434) |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth (Phase 3) |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth (Phase 3) |
| `VEXIS_MAX_REPO_SIZE_MB` | No | Max repo size (default: 500) |
| `VEXIS_MAX_LLM_CALLS_PER_SCAN` | No | Cost control (default: 100) |
| `SCAN_TIMEOUT_SECONDS` | No | Per-scan timeout in seconds (default: 600) |
| `VEXIS_LOG_LEVEL` | No | Log level (default: INFO) |

### Frontend (`.env.local`)

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_API_URL` | YES | Backend API URL |
| `NEXT_PUBLIC_WS_URL` | YES | WebSocket URL |
| `NEXTAUTH_URL` | No | NextAuth base URL (Phase 2 auth) |
| `NEXTAUTH_SECRET` | No | NextAuth secret (Phase 2 auth) |

---

## Troubleshooting

### Tree-sitter parser fails to load

```bash
# Rebuild the language grammar
uv run python -c "
from tree_sitter import Language
Language.build_library('build/languages.so', ['vendor/tree-sitter-python'])
"
```

### LLM calls failing / rate limited

Check `VEXIS_MAX_LLM_CALLS_PER_SCAN` env var. For debugging, set `VEXIS_LOG_LEVEL=DEBUG` to see all LLM prompts and responses.

### Database migration issues

```bash
cd backend
# Check current migration state
uv run alembic current

# Apply all pending migrations
uv run alembic upgrade head

# Roll back one migration
uv run alembic downgrade -1
```

### Frontend can't connect to API

Check that `NEXT_PUBLIC_API_URL` matches where the backend is running. In Docker Compose, the frontend reaches the backend via the `api` service name: `http://api:8000`.

---

*This document is auto-maintained. Update it whenever you add a module, change an API contract, or add a new configuration option.*
