# VEXIS Architecture

Technical deep-dive for contributors and reviewers.

---

## Overview

VEXIS is a dual-engine vulnerability scanner. The deterministic engine (taint analysis) maps every possible source-to-sink data flow. The probabilistic engine (LLM reasoning) evaluates whether each flow is actually exploitable and whether attacks can be chained.

```
┌─────────────────────────────────────────────────────────────────┐
│                          VEXIS Pipeline                          │
├──────────┬──────────────┬──────────────────┬────────────────────┤
│ Ingestion│Taint Analysis│  AI Reasoning    │ Exploit Generation │
│          │              │                  │                    │
│ Tree-    │ PDG Builder  │ Pass 1:          │ PoC Generator      │
│ sitter   │              │ Sanitizer Eval   │                    │
│ parser   │ Call Graph   │                  │ Attack Flow Graph  │
│          │ Builder      │ Pass 2:          │                    │
│ Trust    │              │ Exploit Confirm  │ VulnClassifier     │
│ Boundary │ Cross-file   │                  │ (CWE/OWASP/MITRE) │
│ Rules    │ Linker       │ Pass 3:          │                    │
│          │              │ Chain Discovery  │ Correlation/Dedup  │
│          │ TaintEngine  │                  │                    │
└──────────┴──────────────┴──────────────────┴────────────────────┘
```

---

## Orchestrator (`app/core/orchestrator.py`)

The orchestrator is the entry point for every scan. It runs as a FastAPI `BackgroundTask` and coordinates the full pipeline. Key responsibilities:

- Wraps the entire scan in `asyncio.wait_for` with a configurable timeout (default: 600s)
- Splits multi-file `raw_code` submissions on `# === FILE: name.py ===` markers into temp files
- Skips files over 10,000 lines (logged as `skipped_large`)
- Per-file error isolation: a parse failure on one file does not abort the scan
- Routes to `_run_single_file` (intra-file PDG only) or `_run_cross_file` (merged PDG) based on file count
- Broadcasts real-time progress over WebSocket at each phase transition
- Tracks an `LLMBudget` counter shared across all three reasoning passes

Scan status transitions: `queued` → `parsing` → `taint_analysis` → `reasoning` → `complete` (or `failed` / `timeout`)

---

## Layer 1: Ingestion

### Parser (`app/ingestion/parser.py`)

Uses Tree-sitter with the Python grammar to parse source files into an AST. Extracts:
- Function definitions and calls
- Variable assignments and references
- Import statements
- Control flow structure

Output: `ParsedFile` — contains AST nodes with file/line metadata.

### PDG Builder (`app/ingestion/pdg_builder.py`)

Converts the AST into a **Program Dependency Graph** (PDG) — a NetworkX DiGraph where:
- **Nodes** represent code statements and expressions (with `file`, `line`, `code`, `node_type` attributes)
- **Edges** represent data dependencies (def-use chains), control dependencies, and call edges
- Edge types: `DATA_DEP`, `CONTROL_DEP`, `CALL`, `RETURN`

The PDG is what the taint engine traverses.

### Call Graph Builder (`app/ingestion/call_graph.py`)

For multi-file projects, builds a cross-file call graph by:
1. Collecting all function definitions across all files
2. For each call site, resolving the callee by name to a definition (best-effort)
3. Building `call → callee_entry` edges

Used by the CrossFileLinker to inject inter-file edges into the merged PDG.

### Trust Boundaries (`app/ingestion/trust_boundaries.py`)

Defines the taint rules as pattern lists:

```python
TAINT_SOURCES = [SourcePattern(pattern="request.args.get(", category="http_param"), ...]
TAINT_SINKS   = [SinkPattern(pattern="cursor.execute(", vuln_class="sqli", severity="critical"), ...]
SANITIZERS    = [SanitizerPattern(pattern="html.escape(", is_partial=False), ...]
```

Pattern matching is simple string-contains — fast but approximate. The LLM reasoning pass handles the cases where simple matching is wrong.

---

## Layer 2: Taint Analysis

### TaintEngine (`app/taint/engine.py`)

**Algorithm:** worklist-based forward taint propagation over the PDG.

```
Initialize:
  For each source node matching a TAINT_SOURCE pattern:
    Create TaintState(variable, label, type=TAINTED, path=[source_node])
    Add to worklist

Loop until worklist empty:
  state = worklist.pop()

  For each successor node in PDG:
    If successor matches TAINT_SINK:
      Record TaintPath(source, sink, path, sanitizers)

    If successor matches SANITIZER:
      If is_partial: mark state.type = PARTIALLY_SANITIZED
      Else: discard (taint cleared)

    Else:
      Propagate taint to successor
      Add new TaintState to worklist

  Guard: MAX_PATH_LENGTH=50, MAX_ITERATIONS=10000
```

The engine defines four core dataclasses:
- `TaintSource` — a PDG node that matched a source pattern
- `TaintSink` — a PDG node that matched a sink pattern
- `TaintNode` — a single step in a taint path (node + taint type + human label)
- `TaintPath` — a complete source-to-sink flow (source, sink, path steps, sanitizers encountered, confidence score, vuln_class)

Output: `list[TaintPath]`

### Cross-File Analysis (`app/taint/cross_file.py`)

For multi-file projects:
1. All per-file PDGs are built independently
2. `CrossFileLinker` injects edges at call sites: when file A calls `log_search(client_id)` and `log_search` is defined in file B, an edge is added from A's call node to B's function entry node
3. The merged graph is analyzed by the standard `TaintEngine` via `analyze_project()`

This is what enables detection of the `rate_limiter.py → search.py → logger.py` example.

---

## Layer 3: AI Reasoning

All three passes share an `LLMClient` that implements a Gemini → Ollama → Anthropic fallback chain. Structured output is enforced via `response_schema` on Gemini.

### Pass 1 — Sanitizer Evaluation (`app/reasoning/pass_1_sanitizer.py`)

**Input:** Taint paths that have at least one sanitizer node.
**Task:** Ask the LLM: "Can the sanitizer at line N be bypassed? How?"

If all sanitizers are already marked `is_partial=True` in the trust boundary rules, the pass short-circuits (no LLM call needed — bypass is known).

**Output:** `EvaluatedPath` — adds `sanitizer_effective`, `bypass_possible`, `bypass_technique` to the taint path.

### Pass 2 — Exploit Feasibility (`app/reasoning/pass_2_exploit.py`)

**Input:** `EvaluatedPath` objects from Pass 1.
**Task:** Ask the LLM: "Given the full taint path, is this actually exploitable? Generate the attack vector and payload."

Skips paths where Pass 1 determined the sanitizer is fully effective (`sanitizer_effective=True` and `bypass_possible=False`).

**Output:** `ConfirmedFinding` — adds `exploitable`, `attack_vector`, `payload`, `expected_outcome`, `llm_confidence`.

### Pass 3 — Chain Discovery (`app/reasoning/pass_3_chains.py`)

**Input:** All `CorrelatedFinding` objects with severity in `{info, low, medium}` and `is_false_positive=False`.
**Task:** Group related findings, then ask the LLM for each group: "Do these findings combine into a higher-severity attack?"

**Grouping logic** (`_group_findings`):
- Index every finding by each file its source/sink appears in
- Enumerate all pairs from the same-file index; also enumerate triples when a file has ≥ 3 findings
- If no file-collocated pairs exist, fall back to all pairs across the candidate set
- Cap at 20 groups per scan to control LLM cost

**Acceptance criteria:**
- `chain_found == true` in LLM response
- `confidence >= 0.5` (CHAIN_CONFIDENCE_THRESHOLD)

**Output:** `list[ChainFinding]` — each has `combined_severity`, `attack_steps`, `payload_sequence`, a merged attack flow graph (nodes + edges), and `reasoning`.

**Chain patterns the LLM is prompted to look for:**
- Info leak → auth bypass
- Low-severity write → privilege escalation
- Race condition chains
- Session pollution (shared state tainted by one path, used dangerously by another)
- Indirect SQLi (path A stores attacker data; path B reads it into a query)

### LLM Budget (`app/reasoning/budget.py`)

`LLMBudget(max_calls=N)` is instantiated once per scan in the orchestrator and passed to all three passes. `try_consume()` atomically decrements the counter and returns `False` when exhausted. When the budget runs out, passes skip LLM calls and fall back to taint-only scoring. The number of calls made is recorded in `scan.stats["llm_calls"]`. Configurable via `VEXIS_MAX_LLM_CALLS_PER_SCAN` (default: 100).

---

## Layer 4: Correlation and Exploit Construction

### CorrelationFuser (`app/correlation/fuser.py`)

Combines taint confidence (40%) and LLM confidence (60%) into a `combined_confidence` score. Classifies each finding as `true_positive`, `false_positive`, or `needs_manual_review`.

Severity downgrade logic: if the LLM says not exploitable, severity is reduced by 2 levels.

### Deduplication (`app/correlation/dedup.py`)

**Level 1:** Exact dedup — same `(source_file, source_line, sink_line, vuln_class)` → keep highest confidence.

**Level 2:** Sink collapse — when ≥ 3 paths share the same `(sink_file, sink_line, vuln_class)`, collapse to the best one and annotate with `dedup_count`.

### PoC Generator (`app/exploit/poc_generator.py`)

Constructs concrete proof-of-concept payloads from the confirmed finding data: attack vector (e.g., `GET /search?q=PAYLOAD`), payload string, exploit steps, expected outcome.

### Attack Flow Graph (`app/exploit/attack_flow.py`)

Builds D3.js-compatible node/edge data from a taint path. For chain findings (`vuln_class="chain"`), merges the graphs from all component findings and adds `edge_type="chain"` edges — rendered as dashed purple lines in the frontend.

---

## Adding a New Vulnerability Class

1. **Add sink patterns** in `app/ingestion/trust_boundaries.py`:
   ```python
   SinkPattern(pattern="dangerous_func(", vuln_class="new_class", severity="high")
   ```

2. **Add sanitizer patterns** (if applicable):
   ```python
   SanitizerPattern(pattern="safe_escape(", vuln_class="new_class", is_partial=False)
   ```

3. **Add classifier entry** in `app/exploit/classifier.py`:
   ```python
   VULN_CLASS_TO_CWE["new_class"] = "CWE-XXX"
   VULN_CLASS_TO_OWASP["new_class"] = "AXX:2021 - ..."
   ```

4. **Add test samples** in `tests/vulnerable_samples/new_class/`:
   - `vulnerable_case.py` — should produce ≥ 1 finding
   - `safe_case.py` — should produce 0 findings

5. **Update corpus runner** in `tests/run_full_corpus.py` to include the new samples.

---

## Database Schema

### `scans` table

Stores one row per scan. Key fields:
- `status` — `queued` → `parsing` → `taint_analysis` → `reasoning` → `complete` (or `failed` / `timeout`)
- `source_type` — `raw_code`, `github_url`, `file_upload`, `directory`
- `source_ref` — raw code string, GitHub URL, or filesystem path depending on `source_type`
- `stats` — JSON: `files_found`, `files_parsed`, `taint_paths`, `llm_calls`, `skipped_large`, `parse_errors`, `taint_only_findings`
- `error_message` — set on failure or timeout

### `findings` table

One row per confirmed finding. Key fields:
- `vuln_class` — `"sqli"`, `"cmdi"`, etc., or `"chain"` for Pass 3 findings
- `severity` — `critical`, `high`, `medium`, `low`, `info`
- `taint_path` — JSON: the node-by-node taint flow
- `attack_flow` — JSON: D3 graph data (nodes + edges)
- `poc` — JSON: attack vector, payload, steps, expected outcome
- `chain_data` — JSON (nullable): only set for chain findings — component summary, attack steps, payload sequence
- `llm_reasoning` — full LLM chain-of-thought
- `taint_confidence` / `llm_confidence` / `confidence` — individual and combined scores
- `is_false_positive` — set by CorrelationFuser or manual triage

---

## Configuration

All configuration via environment variables (see `backend/.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL async connection string |
| `GOOGLE_API_KEY` | — | Gemini API key (primary LLM) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (fallback LLM, optional) |
| `REDIS_URL` | — | Redis connection string (task queue) |
| `OLLAMA_BASE_URL` | — | Ollama endpoint (local LLM fallback) |
| `VEXIS_SCAN_TIMEOUT_SECONDS` | `600` | Per-scan timeout |
| `VEXIS_MAX_LLM_CALLS_PER_SCAN` | `100` | LLM call budget per scan |

---

## Performance Characteristics

| Metric | Typical | Worst case |
|--------|---------|-----------|
| Single file, no LLM | < 1s | — |
| 10-file project | 15-30s | 60s |
| LLM calls per taint path | 1-2 | 3 (chain) |
| Files skipped if > N lines | 10,000 lines | — |
| Max groups sent to Pass 3 | 20 per scan | — |
| Scan hard timeout | 600s | configurable |

---

## Frontend

The Next.js 14 frontend (App Router) communicates with the FastAPI backend via:
- REST: `POST /api/v1/scan`, `GET /api/v1/findings/{scan_id}`, `GET /api/v1/stats`
- WebSocket: `/ws/scan/{scan_id}` — receives `{phase, progress, message}` objects for live progress updates

Key components:
- `AttackFlowGraph` (D3.js) — force-directed graph rendering taint paths; chain edges rendered as dashed purple lines using `edge_type="chain"`
- `ScanProgress` — WebSocket consumer that drives the progress bar and phase indicator
- `AuthProvider` / `NavBar` — NextAuth.js session handling; GitHub OAuth login/logout; auth state in navbar
- `middleware.ts` — Next.js edge middleware protecting `/dashboard`, `/scan/*`, `/reports`, `/settings`; redirects to NextAuth sign-in

---

## Sprint 6 — Auth, Storage, and Extended Analysis

### Authentication (`app/core/auth.py`, `app/api/deps.py`, `app/api/routes/auth.py`)

Multi-tenant GitHub OAuth:
1. Frontend calls NextAuth GitHub provider → receives OAuth code
2. Frontend `POST /api/v1/auth/token` with code → backend exchanges with GitHub, upserts `User`, returns signed JWT
3. Backend `get_current_user()` dependency accepts `Authorization: Bearer <jwt>` or `X-VEXIS-API-Key` header
4. All scan/finding queries filter by `user_id` when authenticated; anonymous requests see all (backward compat)
5. Rate limiting: `rate:{user_id}:{date}` Redis key incremented per scan; 3/day free tier, 24h TTL

### Object Storage (`app/core/storage.py`)

MinIO (S3-compatible) with three buckets:
- `code-snapshots/{scan_id}/source.py` — raw submitted code
- `scan-artifacts/{scan_id}/taint_summary.json` — taint analysis metadata
- `reports/{scan_id}.pdf` — generated PDF reports (future)

All MinIO operations fail silently — storage unavailability never breaks a scan.
Presigned URLs (1h TTL) exposed via `GET /api/v1/scan/{id}/download-code` and `GET /api/v1/scan/{id}/artifacts`.

### Second-Order Injection (`app/analysis/second_order.py`)

Three-phase pattern scan across all files:
1. **Write detection** — finds lines matching INSERT/UPDATE patterns where an HTTP source appears within 8 prior lines
2. **Read detection** — finds `.fetchone()`, `.fetchall()`, `objects.get()`, etc.
3. **Sink detection** — within 20 lines after a read: f-string HTML rendering, raw `execute(f"SELECT`)`, `os.system`

Limitation: heuristic proximity-based, not full data-flow. Marked experimental in finding output.

### Pattern-Based Analyzers

**Race Detector (`app/analysis/race_detector.py`)** — CWE-362:
- Scans for `os.path.exists/isfile/isdir` or balance/count check within 5 lines of `os.remove/open/shutil.move` or `balance -=`
- No taint tracking needed — pure structural pattern match

**Auth Analyzer (`app/analysis/auth_analyzer.py`)** — CWE-287:
- Route handler (`@*.route(`) accessing sensitive data without any `@login_required` / `current_user` / JWT decorator
- Token comparison using `==` (timing attack) without `hmac.compare_digest`
- Role/permission read from `request.cookies`/`request.headers`/`request.args`

### New Taint Sinks (Sprint 6)

6 new vulnerability classes in `trust_boundaries.py` as `EXTRA_SINKS` / `EXTRA_SANITIZERS` — loaded into `TaintEngine.__init__` alongside base Python/JS rules:

| Class | Sinks | Key Sanitizer |
|-------|-------|---------------|
| CWE-601 Open Redirect | `redirect(`, `res.redirect(`, `Location` header | `.startswith("/")` |
| CWE-117 Log Injection | `logging.*()`, `logger.*()`, `print()` | `.replace("\n","")` chain |
| CWE-90 LDAP Injection | `.search_s(`, `ldap.search(`, `Connection.search(` | `escape_filter_chars()` |
| CWE-611 XXE | `ET.parse(`, `etree.parse(`, `minidom.parse(`, `xml.sax.parse(` | `defusedxml.` prefix |
