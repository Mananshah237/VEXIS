# VEXIS Architecture

Technical deep-dive for contributors and reviewers.

---

## Overview

VEXIS is a dual-engine vulnerability scanner. The deterministic engine (taint analysis with CCSM) maps every possible source-to-sink data flow and scores each path with a continuous danger score. The probabilistic engine (LLM reasoning) evaluates whether each flow is actually exploitable, whether attacks can be chained, and generates runnable exploit scripts.

```
┌──────────────────────────────────────────────────────────────────────┐
│                           VEXIS Pipeline                              │
├──────────┬──────────────┬────────────────────┬────────────────────────┤
│ Ingestion│Taint Analysis│   AI Reasoning     │  Exploit Construction  │
│          │   (CCSM)     │                    │                        │
│ Tree-    │ PDG Builder  │ Pass 1:            │ Script Generator       │
│ sitter   │              │ Sanitizer Eval     │ (runnable Python PoC)  │
│ parser   │ Graph Folder │                    │                        │
│          │ (passthrough │ Pass 2:            │ PoC Generator          │
│ Trust    │  collapse)   │ Exploit Confirm    │ (payloads + steps)     │
│ Boundary │              │                    │                        │
│ Rules    │ Call Graph   │ Pass 3:            │ Attack Flow Graph      │
│ (CCSM)   │ Builder      │ Chain Discovery    │ (D3.js, chain edges)   │
│          │              │                    │                        │
│          │ Cross-file   │ Pass 4:            │ VulnClassifier         │
│          │ Linker       │ Business Logic     │ (CWE/OWASP/MITRE)      │
│          │              │ Discovery          │                        │
│          │ TaintEngine  │                    │ Correlation/Dedup      │
└──────────┴──────────────┴────────────────────┴────────────────────────┘
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
- Tracks an `LLMBudget` counter shared across all four reasoning passes
- Unfolds graph-folded taint paths after taint analysis, before LLM reasoning passes

Scan status transitions: `queued` → `parsing` → `taint_analysis` → `reasoning` → `complete` (or `failed` / `timeout`)

---

## Layer 1: Ingestion

### Parser (`app/ingestion/parser.py`)

Uses Tree-sitter with Python, JavaScript, TypeScript, and TSX grammars to parse source files into an AST. Extracts:
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
- Node types: `STATEMENT`, `ASSIGNMENT`, `CALL`, `CONDITION`, `FUNCTION_DEF`, `RETURN`, `PARAMETER`, `IMPORT`

The PDG is what the taint engine traverses.

### Graph Folder (`app/ingestion/graph_folder.py`)

Collapses passthrough chains in the PDG before taint traversal to reduce worklist iterations.

**Passthrough node:** exactly 1 DATA_DEP predecessor, exactly 1 DATA_DEP successor, not an anchor type (CALL, CONDITION, FUNCTION_DEF, RETURN, PARAMETER), and not matching any source/sink/sanitizer pattern.

**Folding:** chains `A → B → C → D` where B and C are passthroughs become `A → D`. The new edge stores `folded_nodes=[B_data, C_data]`. After taint analysis, `unfold_path()` restores the full intermediate node list before the path is serialized — the API always returns complete paths.

Compression ratio logged at INFO when folding occurs. For most real-world PDGs the optimization is latent (dual STATEMENT+ASSIGNMENT node representation prevents many passthroughs); it activates on simpler single-variable chains.

### Call Graph Builder (`app/ingestion/call_graph.py`)

For multi-file projects, builds a cross-file call graph by:
1. Collecting all function definitions across all files
2. For each call site, resolving the callee by name to a definition (best-effort)
3. Building `call → callee_entry` edges

Used by the CrossFileLinker to inject inter-file edges into the merged PDG.

### Trust Boundaries / CCSM (`app/ingestion/trust_boundaries.py`)

Defines the taint rules as pattern lists with **Continuous Constraint Sanitizer Model** (CCSM):

```python
# Sources
TAINT_SOURCES = [SourcePattern(pattern="request.args.get", source_type="http_param"), ...]

# Sinks
TAINT_SINKS = [SinkPattern(pattern="cursor.execute", vuln_class="sqli", severity="critical"), ...]

# Sanitizers — constraint_power (0.0=no effect, 1.0=full elimination)
SANITIZERS = [
    SanitizerPattern("int(",        constraint_power=0.95, effective_for=["sqli","cmdi",...]),
    SanitizerPattern("html.escape(", constraint_power=0.90, effective_for=["xss"]),
    SanitizerPattern(".replace(",   constraint_power=0.15, effective_for=["sqli","log_injection"]),
    SanitizerPattern(".strip(",     constraint_power=0.05, effective_for=["log_injection"]),
    ...
]
```

`effective_for` makes sanitizers context-sensitive: `html.escape()` provides 0 constraint for SQLi sinks even if encountered on the taint path. The `is_partial` property is backward-compatible (`constraint_power < 0.95`).

**60 sanitizer patterns** across Python, JavaScript, redirect, log, LDAP, and XXE categories.

---

## Layer 2: Taint Analysis (CCSM)

### TaintEngine (`app/taint/engine.py`)

**Algorithm:** worklist-based forward taint propagation over the (folded) PDG with continuous danger scoring.

```
Initialize:
  For each source node matching a TAINT_SOURCE pattern:
    Create TaintState(variable, label, type=TAINTED, path=[source_node], danger_score=1.0)
    Add to worklist

Loop until worklist empty:
  state = worklist.pop()

  If state.danger_score < DANGER_THRESHOLD:
    skip (early termination — CCSM pruned this path)

  For each DATA_DEP successor node in PDG:
    If successor matches TAINT_SINK:
      effective_danger = calc_effective_danger(path_sanitizers, sink.vuln_class)
      If effective_danger >= DANGER_THRESHOLD:
        Record TaintPath(..., confidence=effective_danger)

    If successor matches SANITIZER:
      new_danger = state.danger_score * (1 - sanitizer.constraint_power)
      If new_danger < DANGER_THRESHOLD: skip (early terminate)
      Propagate with new_danger, mark PARTIALLY_SANITIZED

    Else:
      Propagate taint to successor, add new TaintState to worklist

  Guard: MAX_PATH_LENGTH=50, MAX_ITERATIONS=10000
```

**CCSM at the sink:** `_calc_effective_danger(sanitizers, vuln_class)` only counts sanitizers whose `effective_for` list includes the sink's vuln_class. This enables:
- `html.escape()` before an f-string SQL query → effective_danger = 1.0 → SQLi still fires
- `html.escape()` before innerHTML → effective_danger = 0.10 → XSS suppressed (< 0.15 threshold)
- `int()` before any sink → effective_danger = 0.05 → all types suppressed

**`taint_confidence`** is set to `effective_danger_score` (± small severity adjustment). A path with no sanitizers gets `taint_confidence=1.0`. A path through `.replace(` gets `taint_confidence=0.85`. The LLM then layers its own `llm_confidence` on top; the orchestrator combines them (40% taint, 60% LLM).

**`VEXIS_DANGER_THRESHOLD`** (default: 0.15) is configurable via environment variable.

The engine defines four core dataclasses:
- `TaintSource` — a PDG node that matched a source pattern
- `TaintSink` — a PDG node that matched a sink pattern
- `TaintNode` — a single step in a taint path (node + taint type + human label)
- `TaintState` — propagation state (variable, taint type, path, sanitizers, `danger_score`)
- `TaintPath` — a complete source-to-sink flow (source, sink, path steps, sanitizers, confidence, vuln_class)

Output: `list[TaintPath]`

### Cross-File Analysis (`app/taint/cross_file.py`)

For multi-file projects:
1. All per-file PDGs are built independently
2. `CrossFileLinker` injects edges at call sites: when file A calls `log_search(client_id)` and `log_search` is defined in file B, an edge is added from A's call node to B's function entry node
3. The merged graph is folded by `fold_pdg()` inside `TaintEngine.analyze()`
4. The folded merged graph is analyzed by the standard `TaintEngine` via `analyze_project()`

This is what enables detection of the `rate_limiter.py → search.py → logger.py` example.

---

## Layer 3: AI Reasoning

All four passes share an `LLMClient` that implements a Gemini → Ollama → Anthropic fallback chain. Structured output is enforced via `response_schema` on Gemini. Triple-quoted Python strings in JSON responses (Ollama artifact) are recovered via regex extraction in `_parse_json`.

### Pass 1 — Sanitizer Evaluation (`app/reasoning/pass_1_sanitizer.py`)

**Input:** Taint paths that have at least one sanitizer node.
**Task:** Ask the LLM: "Can the sanitizer at line N be bypassed? How?"

If all sanitizers are already low-constraint (`constraint_power < 0.95`), the pass short-circuits — bypass is structurally guaranteed.

**Output:** `EvaluatedPath` — adds `sanitizer_effective`, `bypass_possible`, `bypass_technique` to the taint path.

### Pass 2 — Exploit Feasibility (`app/reasoning/pass_2_exploit.py`)

**Input:** `EvaluatedPath` objects from Pass 1.
**Task:** Ask the LLM: "Given the full taint path, is this actually exploitable? Generate the attack vector and payload."

Skips paths where Pass 1 determined the sanitizer is fully effective.

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

**Output:** `list[ChainFinding]` — each has `combined_severity`, `attack_steps`, `payload_sequence`, a merged attack flow graph, and `reasoning`.

**Chain patterns the LLM is prompted to look for:**
- Info leak → auth bypass
- Low-severity write → privilege escalation
- Race condition chains
- Session pollution (shared state tainted by one path, used dangerously by another)
- Indirect SQLi (path A stores attacker data; path B reads it into a query)

### Pass 4 — Business Logic Discovery (`app/reasoning/pass_4_business_logic.py`)

**Input:** All parsed files for the scan.
**Task:** LLM examines function signatures, route handlers, access control patterns, and data flows that the taint engine cannot model (missing auth checks, insecure direct object references, client-controllable roles).

This pass runs even when the taint engine finds no paths — it's a pure LLM analysis of the semantic structure of the code.

**Output:** Additional `CorrelatedFinding` objects tagged `taint_path.type = "business_logic_discovery"` with an AI badge in the UI.

### LLM Budget (`app/reasoning/budget.py`)

`LLMBudget(max_calls=N)` is instantiated once per scan in the orchestrator and passed to all four passes. `try_consume()` atomically decrements the counter and returns `False` when exhausted. When the budget runs out, passes skip LLM calls and fall back to taint-only scoring. The number of calls made is recorded in `scan.stats["llm_calls"]`. Configurable via `VEXIS_MAX_LLM_CALLS_PER_SCAN` (default: 100).

---

## Layer 4: Correlation and Exploit Construction

### CorrelationFuser (`app/correlation/fuser.py`)

Combines taint confidence (40%) and LLM confidence (60%) into a `combined_confidence` score. With CCSM, taint confidence is the `effective_danger_score` — not a magic number, but a direct measurement of how much the path was constrained by sanitizers effective for the specific vuln class.

Severity downgrade logic: if the LLM says not exploitable, severity is reduced by 2 levels.

### Deduplication (`app/correlation/dedup.py`)

**Level 1:** Exact dedup — same `(source_file, source_line, sink_line, vuln_class)` → keep highest confidence.

**Level 2:** Sink collapse — when ≥ 3 paths share the same `(sink_file, sink_line, vuln_class)`, collapse to the best one and annotate with `dedup_count`.

### Exploit Script Generator (`app/exploit/script_generator.py`)

LLM generates a full runnable Python script per confirmed finding. The script is stored in `findings.exploit_script` and exposed via:
- `GET /api/v1/finding/{id}/exploit` — download as `.py`
- Inline on the scan results page — expandable code block with Copy + Download buttons
- Full view on the finding detail page

Fallback: if the LLM fails or produces a malformed script, a template-based PoC is used instead (`result.get("script") or base_script`). Triple-quoted Python docstrings in LLM JSON output are handled via regex recovery in `_parse_json`.

### PoC Generator (`app/exploit/poc_generator.py`)

Constructs concrete proof-of-concept payloads from the confirmed finding data: attack vector (e.g., `GET /search?q=PAYLOAD`), payload string, exploit steps, expected outcome.

### Attack Flow Graph (`app/exploit/attack_flow.py`)

Builds D3.js-compatible node/edge data from a taint path. For chain findings (`vuln_class="chain"`), merges the graphs from all component findings and adds `edge_type="chain"` edges — rendered as dashed purple lines in the frontend.

---

## Semgrep Differential Analysis (`app/api/routes/differential.py`)

Runs Semgrep in parallel with VEXIS on every scan and computes a three-column comparison:

- **VEXIS-only:** findings taint analysis / LLM detected but Semgrep missed
- **Overlap:** findings both tools agree on (confidence booster)
- **Semgrep-only:** patterns Semgrep found that VEXIS missed (useful for adding new sinks)

Overlap detection uses file + line proximity (±5 lines) rather than exact match, since Semgrep reports the pattern location while VEXIS reports the sink.

---

## Adding a New Vulnerability Class

1. **Add sink patterns** in `app/ingestion/trust_boundaries.py`:
   ```python
   SinkPattern(pattern="dangerous_func(", vuln_class="new_class", severity="high")
   ```

2. **Add sanitizer patterns** with calibrated `constraint_power`:
   ```python
   SanitizerPattern(
       pattern="safe_escape(",
       constraint_power=0.90,          # 0.0=no effect, 1.0=full elimination
       effective_for=["new_class"],     # context-sensitive
   )
   ```

3. **Add classifier entry** in `app/exploit/classifier.py`:
   ```python
   VULN_CLASS_TO_CWE["new_class"] = "CWE-XXX"
   VULN_CLASS_TO_OWASP["new_class"] = "AXX:2021 - ..."
   ```

4. **Add test samples** in `tests/vulnerable_samples/new_class/`:
   - `vulnerable_case.py` — should produce ≥ 1 finding
   - `safe_case.py` — should produce 0 findings (false positive check)

5. **Update corpus runner** in `tests/run_full_corpus.py` to include the new samples.

---

## Database Schema

### `scans` table

Stores one row per scan. Key fields:
- `status` — `queued` → `parsing` → `taint_analysis` → `reasoning` → `complete` (or `failed` / `timeout`)
- `source_type` — `raw_code`, `github_url`, `file_upload`, `directory`
- `source_ref` — raw code string, GitHub URL, or filesystem path depending on `source_type`
- `stats` — JSON: `files_found`, `files_parsed`, `taint_paths`, `llm_calls`, `skipped_large`, `parse_errors`, `taint_only_findings`, `exploit_scripts_generated`, `semgrep_summary`
- `error_message` — set on failure or timeout

### `findings` table

One row per confirmed finding. Key fields:
- `vuln_class` — `"sqli"`, `"cmdi"`, etc., or `"chain"` for Pass 3 findings
- `severity` — `critical`, `high`, `medium`, `low`, `info`
- `taint_path` — JSON: the node-by-node taint flow (fully unfolded, includes graph-folded intermediate nodes)
- `attack_flow` — JSON: D3 graph data (nodes + edges)
- `poc` — JSON: attack vector, payload, steps, expected outcome
- `chain_data` — JSON (nullable): only set for chain findings — component summary, attack steps, payload sequence
- `exploit_script` — TEXT (nullable): full runnable Python PoC script
- `llm_reasoning` — full LLM chain-of-thought
- `taint_confidence` — effective danger score from CCSM (0.0–1.0)
- `llm_confidence` / `confidence` — LLM score and combined score (40% taint + 60% LLM)
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
| `MINIO_ENDPOINT` | `localhost:9000` | Internal MinIO address |
| `MINIO_PUBLIC_ENDPOINT` | `""` | Public-facing URL base for presigned URLs |
| `VEXIS_SCAN_TIMEOUT_SECONDS` | `600` | Per-scan timeout |
| `VEXIS_MAX_LLM_CALLS_PER_SCAN` | `100` | LLM call budget per scan |
| `VEXIS_DANGER_THRESHOLD` | `0.15` | CCSM early-termination threshold |

---

## Performance Characteristics

| Metric | Typical | Notes |
|--------|---------|-------|
| Single file, no LLM | < 1s | Pure taint + graph fold |
| 10-file Python project | 20–40s | Includes LLM calls |
| 20-file real-world app | 60–90s | `we45/Vulnerable-Flask-App`: 61s |
| LLM calls per taint path | 1–2 | 3 when Pass 3 chain found |
| Files skipped if > N lines | 10,000 lines | Configurable |
| Max groups sent to Pass 3 | 20 per scan | Controls LLM cost |
| Scan hard timeout | 600s | Configurable |
| CCSM early termination | danger < 0.15 | Prunes paths through strong sanitizers |
| Graph fold compression | 0–40% | Depends on code structure |

---

## Frontend

The Next.js 14 frontend (App Router) communicates with the FastAPI backend via:
- REST: `POST /api/v1/scan`, `GET /api/v1/scan/{id}/findings`, `GET /api/v1/stats`
- WebSocket: `/ws/scan/{scan_id}` — receives `{phase, progress, message}` objects for live progress updates

Key pages:
- `/` — Landing page
- `/dashboard` — Recent scans, global stats
- `/scan/[id]` — Scan results: finding cards with inline exploit scripts, severity breakdown, Semgrep differential tab
- `/scan/[id]/finding/[fid]` — Finding detail: full taint path, attack flow graph, exploit script

Key components:
- `AttackFlowGraph` (D3.js) — force-directed graph rendering taint paths; chain edges rendered as dashed purple lines using `edge_type="chain"`
- `ScanProgress` — WebSocket consumer that drives the progress bar and phase indicator
- `AuthProvider` / `NavBar` — NextAuth.js session handling; GitHub OAuth login/logout
- `middleware.ts` — Next.js edge middleware protecting `/dashboard`, `/scan/*`; redirects to NextAuth sign-in

### Exploit Scripts in the UI

Every finding with an `exploit_script` shows an `⚡ Exploit` badge on its card in the scan results list. Clicking **▾ show** expands an inline dark-themed code block with:
- Filename (`exploit_{id}.py`)
- **Copy** button (clipboard)
- **Download** button (`.py` file via `/api/v1/finding/{id}/exploit`)
- Scrollable syntax-highlighted Python code

The same script is also accessible on the finding detail page (`/scan/[id]/finding/[fid]`).

---

## Sprint History

| Sprint | Key Features |
|--------|-------------|
| 1–3 | Core taint engine, PDG builder, Python source/sink/sanitizer rules |
| 4 | JS/TS support, framework detection, cross-file taint, Pass 1/2/3 |
| 5 | Second-order injection, race detector, auth analyzer, 6 new CWE classes |
| 6 | GitHub OAuth, MinIO storage, PDF reports, GitHub Action, incremental scanning |
| 7 | Exploit script generation, Pass 4 (business logic), Semgrep differential, performance optimization |
| 8 | CCSM (continuous sanitizer scoring), Graph Folding, inline exploit UI, presigned URL fix |
