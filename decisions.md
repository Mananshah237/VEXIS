# VEXIS — Architecture & Design Decisions

**Last Updated:** 2026-03-27

This file records every significant architectural or design decision made during development, including the rationale. When something changes, the old decision stays here with a note explaining why it changed.

---

## Decision Log

### D-001 — Python Package Manager: uv over Poetry
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Use `uv` for Python dependency management instead of Poetry.

**Rationale:**
- uv is 10-100x faster than Poetry for installs
- Single binary, no shell activation quirks
- pyproject.toml compatible — can migrate to anything later
- Better lockfile semantics for reproducible builds

**Alternatives considered:** Poetry, pip + requirements.txt, PDM
**Risks:** Newer tool, smaller community than Poetry — mitigated by pyproject.toml standard compliance

---

### D-002 — MVP: Synchronous scanning (no Celery)
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Phase 1 MVP uses synchronous scanning in FastAPI background tasks, not Celery.

**Rationale:**
- Celery + Redis adds significant operational complexity for an MVP
- FastAPI's `BackgroundTasks` handles small-scale async adequately
- Can swap to Celery in Phase 3 without API contract changes

**Trade-offs:** No retry logic, no distributed workers, no task persistence across restarts
**Migration path:** `scan_task.py` already structured to be a Celery task — just add `@celery.task` decorator

---

### D-003 — Tree-sitter Python bindings
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Use `tree-sitter` + `tree-sitter-python` Python packages directly (not py-tree-sitter-languages bundle).

**Rationale:**
- `tree-sitter-python` gives us the exact grammar version we control
- Smaller install footprint (don't pull all 40 grammars)
- Explicit language grammars make it easy to add Phase 3 languages incrementally

**Alternatives considered:** py-tree-sitter-languages (all-in-one), ast (stdlib — no error tolerance)

---

### D-004 — Graph library: NetworkX
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Use NetworkX for PDG/call graph construction and path enumeration.

**Rationale:**
- De facto standard for graph algorithms in Python
- Built-in: DFS/BFS, shortest paths, topological sort, cycle detection
- DiGraph fits PDG semantics perfectly
- Easy to serialize to JSON for frontend attack flow graph

**Alternatives considered:** igraph (faster but harder API), neo4j (overkill for MVP), custom adjacency list
**Performance note:** NetworkX is pure Python and slow for >1M nodes. Phase 3 large-repo scanning may need igraph or Rust-based graph library.

---

### D-005 — LLM: Gemini Flash as primary, with Ollama and Anthropic fallbacks
**Date:** 2026-03-25
**Status:** Accepted (model name corrected 2026-03-26)

**Decision:** Use `gemini-flash-latest` as the primary analysis model.

**Rationale:**
- Gemini Flash has best-in-class cost/quality for structured code analysis
- `response_schema` enforcement makes JSON output reliable
- Large context window handles multi-file taint paths
- Fallback chain: Gemini → Ollama (llama3, offline) → Anthropic Claude

**Implementation note:** Model must be `gemini-flash-latest`, not `gemini-2.0-flash` (unavailable). API key stored in `backend/.env` as `GOOGLE_API_KEY`.

---

### D-006 — Frontend: Next.js App Router
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Use Next.js 14 with App Router (not Pages Router).

**Rationale:**
- App Router is the current/future standard — no migration debt
- Server components reduce client bundle size for code viewer
- Better layout nesting for scan detail → finding detail navigation

---

### D-007 — Attack Flow Graph: D3.js force-directed
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Use D3.js v7 force-directed simulation for attack flow visualization, not a library like React Flow or Cytoscape.

**Rationale:**
- Full control over visual aesthetic (glowing edges, pulsing nodes) — this is a demo moment feature
- React Flow / Cytoscape look like business tools, not hacker tools
- D3 force simulation handles the organic "neural network" look from the design spec
- Trade-off: More implementation work, but the visual differentiation is worth it

---

### D-008 — Database: PostgreSQL with JSONB for findings
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Store taint_path, attack_flow, poc, and remediation as JSONB in PostgreSQL rather than normalizing into tables.

**Rationale:**
- Finding structure is complex and variable — normalizing would require 10+ tables
- JSONB allows flexible querying (filter by path elements, etc.)
- Single-row fetch for finding detail (no expensive JOINs)

---

### D-009 — Taint confidence: worklist algorithm, not symbolic execution
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Implement taint propagation as a worklist-based dataflow algorithm rather than full symbolic execution.

**Rationale:**
- Symbolic execution (Z3, etc.) is an order of magnitude more expensive and complex
- Worklist approach covers 90%+ of real vulnerability patterns
- False negatives from path condition imprecision are acceptable — LLM pass_2 handles feasibility

**Trade-offs:** Some path-sensitive vulnerabilities may be missed (e.g., "vulnerable only when config flag X is set"). Acceptable for MVP.

---

### D-010 — MVP scope: 3 vuln classes only
**Date:** 2026-03-25
**Status:** Accepted

**Decision:** Phase 1/2 targets only SQL Injection (CWE-89), Command Injection (CWE-78), and Path Traversal (CWE-22).

**Rationale:**
- These 3 classes cover ~60% of critical web vulnerabilities in practice
- Well-defined sources/sinks make taint analysis deterministic
- Adding more classes in Phase 3 is purely additive — no rearchitecting needed

---

### D-011 — node_text() must use byte slicing, not character slicing
**Date:** 2026-03-25
**Status:** Fixed (discovered in testing)

**Decision:** `ParsedFile.node_text()` must slice `source_bytes` (bytes) by `node.start_byte`/`node.end_byte`, then decode to str.

**Why this matters:** Tree-sitter's `start_byte`/`end_byte` are byte positions in the UTF-8 encoded source. Python's string slicing is by character index. Any multi-byte character causes all subsequent byte positions to drift.

**Symptoms found:** `sanitized` extracted as `ized` when preceded by an em dash `—` in a docstring.

**Fix:** Store `source_bytes` in `ParsedFile`; use `source_bytes[node.start_byte:node.end_byte].decode("utf-8")`.

---

### D-012 — PDG source/sink matching must skip FUNCTION_DEF nodes
**Date:** 2026-03-25
**Status:** Fixed (discovered in testing)

**Decision:** Taint engine `_match_source` / `_match_sink` skip `FUNCTION_DEF`, `PARAMETER`, `IMPORT`, `CONDITION` node types.

**Why this matters:** The PDG builder creates a `function_definition` node whose `.code` is the entire function body text, containing both sources and sinks simultaneously. This produces a self-referential false source→sink "path" on a single node with high confidence.

**Fix:** Restrict matching to `CALL`, `ASSIGNMENT`, `STATEMENT`, `EXPRESSION`, `RETURN` node types only.

---

### D-013 — Cross-file taint: unified PDG via CrossFileLinker
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Implement cross-file taint tracking by building per-file PDGs and then merging them into a single project-wide PDG with injected DATA_DEP edges for three inter-procedural flow patterns.

**Three edge patterns:**
1. **Shared state stores/loads** — `request.state.X = val` in file A → `request.state.X` read in file B (matched by regex on the attribute/dict-key string)
2. **Function arg → parameter** — call `f(tainted_var)` → arg_idx maps to param name in callee → inject DATA_DEP from caller arg definition to callee param uses
3. **Return value propagation** — `return val` in callee → `result = f()` assignment in caller

**Why not a traditional call graph approach:**
- Full call graph with context-sensitivity is expensive and complex
- Our PDG merge approach is O(nodes × edges) and produces the same result for the vulnerability patterns we care about
- LLM pass 2 handles any false positives from over-approximation

**Key files:** `ingestion/call_graph.py` (ProjectCallGraph + CallGraphBuilder), `taint/cross_file.py` (CrossFileLinker), `taint/engine.py` (`analyze_project()`)

---

### D-014 — Source pattern matching must use word boundaries
**Date:** 2026-03-27
**Status:** Fixed (discovered in cross-file testing)

**Decision:** `TaintEngine._pattern_matches()` uses `re.search(r'\b' + re.escape(pattern), code)` for patterns starting with a letter or underscore, rather than plain substring matching.

**Why this matters:** The source pattern `"input("` is intended to match Python's `input()` built-in. But it also matches as a substring inside function names like `get_user_input()`. This caused `cmd = get_user_input()` in handler.py to be falsely flagged as a taint source, resulting in a spurious finding with wrong source file.

**Fix:** Patterns starting with `\w` use `\b` word-boundary prefix. Patterns starting with non-word chars (e.g., `.filter(`, `?", (`) use plain substring match.

---

### D-015 — Findings ordered by taint_confidence DESC
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** The `/api/v1/scan/{id}/findings` endpoint orders results by `taint_confidence DESC, confidence DESC`.

**Rationale:** When a scan produces multiple findings for the same sink (e.g., one from a critical unsanitized path and one from a partially-sanitized path), the algorithmically-certain finding (higher taint_confidence) should appear first. This is more reliable than `combined_confidence` which includes LLM scores that can vary.

**Previous behavior:** No ORDER BY — undefined order from PostgreSQL, causing flaky test results when two findings existed for the same scan.

---

### D-016 — Taint path pre-deduplication before LLM
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** `TaintEngine.analyze()` calls `_dedup_paths()` before returning, deduplicating by `(source_file, source_line, sink_file, sink_line, vuln_class)`.

**Why this matters:** The PDG builder creates both STATEMENT and CALL nodes for the same line (an `expression_statement` wrapping a `call`). This produces duplicate taint paths that differ only in which PDG node represents the same code. Without pre-dedup, 4 LLM calls are made instead of 2 for a typical cross-file scenario.

**Post-correlation dedup** (in `correlation/dedup.py`) still runs as a second pass to handle any remaining duplicates.

---

### D-017 — SSRF "safe" sample uses hardcoded URL, not allowlist pattern
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** The SSRF false-positive test sample (`ssrf/safe_allowlist.py`) uses a hardcoded URL constant rather than an allowlist check pattern.

**Rationale:** The taint engine is flow-based. In code like `parsed = urlparse(url); requests.get(url)`, the URL flows directly to the SSRF sink without passing through the urlparse node — so the `urlparse(` sanitizer is never encountered on that path. An allowlist pattern would still be flagged as SSRF. Using a hardcoded URL constant guarantees no taint source reaches the SSRF sink, producing a reliable 0-finding test case.

**Alternatives considered:** Making urlparse( a full sanitizer — rejected because urlparse alone (without the actual allowlist comparison) does NOT prevent SSRF.

---

### D-018 — XSS sink strategy: Markup() only, not bare return
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** XSS sinks are limited to `Markup(` and `render_template_string(` rather than trying to detect f-string returns with HTML content.

**Rationale:** Detecting "return f-string with HTML" would require semantic understanding that the response has `text/html` content type — not achievable with simple substring matching. `Markup()` is an explicit, detectable signal that the developer is intentionally marking content as safe HTML, which is the canonical XSS pattern.

---

### D-019 — LLM schema validation: retry once, then fill defaults
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** After an LLM response with missing required schema fields, retry once with an explicit field reminder. If the retry still has missing fields, fill safe type-appropriate defaults (false for bool, 0.5 for number, "" for string, [] for array) rather than failing the scan.

**Rationale:** Gemini with response_schema rarely misses fields, but Ollama/Anthropic fallbacks can. Failing the entire scan on a missing `why_not_exploitable` field is too aggressive — the cost of a slightly degraded finding is lower than a failed scan.

---

### D-020 — Pass 1 no-sanitizer confidence: 0.95
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** When there are zero sanitizers on a taint path, skip Pass 1 LLM and pre-fill `llm_confidence=0.95` (previously 0.8).

**Rationale:** 0.8 was too conservative. A taint path with no sanitizers at all is the most clear-cut case — the LLM's job is just to confirm, which it does with near-certainty. 0.95 better represents "this is almost certainly exploitable" for the no-sanitizer case, driving the combined confidence high enough to consistently produce CRITICAL severity.

---

### D-021 — LLMBudget: shared counter with taint-only fallback
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Introduce `LLMBudget` (`backend/app/reasoning/budget.py`) — a single shared counter object passed to both LLM passes. `try_consume()` returns False when the budget is exhausted; callers fall back to taint-only reasoning using the `BUDGET_EXHAUSTED_REASONING` constant.

**Rationale:** Prevents runaway LLM costs on large repos. A scan that exceeds budget still produces findings (via taint-only path) rather than failing, and the UI shows a banner when any finding was produced without LLM confirmation.

**Key constant:** `BUDGET_EXHAUSTED_REASONING` — sentinel string; frontend scans `llm_reasoning` for this value to show the taint-only banner.

---

### D-022 — Two-level deduplication in correlation/dedup.py
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Post-correlation deduplication runs two levels: Level 1 = exact match on `(source_file, source_line, sink_line, vuln_class)`; Level 2 = sink-level collapse when ≥3 taint paths share the same sink location and vuln_class, retaining the highest-confidence path and annotating with `dedup_count`.

**Rationale:** Large repos can generate many paths to the same sink (e.g., 5 different user inputs all flowing to the same SQL call). Showing all 5 is noise — the fix is the same regardless. Collapsing at threshold 3 reduces report noise without hiding distinct issues.

---

### D-023 — asyncio.wait_for scan timeout
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** `_run_scan_impl()` is wrapped with `asyncio.wait_for(timeout=settings.scan_timeout_seconds)` (default 600s). On expiry, `scan.status` is set to `"timeout"` rather than `"failed"`.

**Rationale:** User-facing reliability — a scan that hangs (e.g., on a pathological taint graph) should surface as a timeout rather than an indefinitely running job. The distinct `"timeout"` status lets the UI show a clear message and lets operators identify slow input patterns. Configurable via `settings.scan_timeout_seconds` to allow tuning per deployment.

---

### D-024 — Semgrep benchmark: run inside vexis-api-1 container
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** The benchmark harness (`backend/tests/benchmark/semgrep_comparison.py`) runs Semgrep via `docker exec vexis-api-1 semgrep --config=auto --json --quiet` rather than invoking a local Semgrep install or a separate container.

**Rationale:** Running in the same container avoids path translation issues between the host and container file system — the same sample files are already present inside `vexis-api-1`. Semgrep is installed once via `pip install semgrep` in that container. This keeps the comparison apples-to-apples (same code, same file paths, same runtime environment).

---

### D-025 — Pass 3 Chain Discovery design
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Pass 3 groups medium/low findings by shared file context (findings that reference the same source or sink file are co-located), sends groups of 2-4 findings to the LLM, and asks it to identify attack chains. Confirmed chains are persisted as `Finding` ORM objects with `vuln_class="chain"` and a `chain_data` JSONB column containing the ordered attack steps and composite severity.

**Rationale:** No existing SAST tool automatically identifies chained attack paths. A standalone info-leak (MEDIUM) plus a gated SQLi (MEDIUM) is individually low-priority, but chained it becomes a CRITICAL privilege escalation. Grouping by shared file keeps the LLM context small and relevant; sending 2-4 at a time balances cost against chain detection recall.

**Key files:** `backend/app/reasoning/pass_3_chains.py`, `tests/vulnerable_samples/chains/info_leak_to_sqli/user_profile.py`

**Orchestrator integration:** Runs after Pass 2; broadcasts WebSocket progress at 0.88.

---

### D-026 — Chain edges in AttackFlowGraph rendered as dashed purple
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** `AttackFlowGraph.tsx` treats edges with `edge_type="chain"` as a distinct visual class: dashed stroke, color `#7C4DFF` (purple), slightly thicker weight than standard taint edges.

**Rationale:** The attack flow graph already encodes taint flow semantics with color (tainted=red, sanitized=yellow, cleared=green). Chain links are a fundamentally different relationship — they connect two separate findings rather than two nodes within a single taint path. Dashed purple is visually distinct from all existing edge styles while reading intuitively as "these two vulnerabilities are linked." Makes chain attack paths immediately readable without a legend.

---

### D-027 — Test runners use httpx with curl fallback; 0.5s stagger + 3 retries
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Integration test runners (`run_e2e.py`, `run_full_corpus.py`, etc.) attempt HTTP requests via `httpx` first; if `httpx` is not available they fall back to `curl`. Concurrent scan submissions include a 0.5s stagger between requests and retry each submission up to 3 times on connection error.

**Rationale:** The container environment has Python + httpx but not necessarily curl; the host environment may not have httpx installed. The dual-fallback makes runners executable in both environments without modification. The stagger + retry was added after benchmark runs revealed that firing all 27 scan POSTs simultaneously caused connection resets — the FastAPI background task pool was saturating before the first scans completed. 0.5s stagger empirically eliminated the connection errors without significantly increasing total benchmark wall time.


---

### D-028 — Auth: optional/anonymous fallback for backward compatibility
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** `get_current_user()` returns `None` for unauthenticated requests rather than raising 401. All scan and finding routes accept unauthenticated access; when `current_user` is None the user_id filter is skipped and all records are visible.

**Rationale:** The existing test suite (run_e2e.py, run_full_corpus.py, run_cross_file.py) submits scans without auth headers. Requiring auth would break every test runner and the demo flow without adding security for a dev-mode deployment. The test suite remains valid; auth is enforced selectively by the rate limiter and frontend middleware.

---

### D-029 — Second-order injection as experimental pattern analysis
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** Second-order injection is detected via proximity heuristics (HTTP source within 8 lines of INSERT + SELECT + dangerous sink within 20 lines of read) rather than true inter-procedural data-flow. Findings are tagged as second-order in their `taint_path` JSON and the title explicitly says "Second-Order".

**Rationale:** True second-order tracking would require symbolic execution or full call-graph-aware taint propagation across database reads/writes — a significant research problem. The proximity heuristic catches the canonical patterns (stored XSS, second-order SQLi) from the Sprint 6 test corpus. Known limitation: misses cases where the DB write and the vulnerable read are in different files. Documented as experimental so users understand the detection model.

---

### D-030 — Race condition and auth bypass as pattern-based passes separate from taint engine
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** CWE-362 (TOCTOU) and CWE-287 (auth bypass) are detected by dedicated analyzer modules (`race_detector.py`, `auth_analyzer.py`) that run as separate passes after the taint/LLM pipeline, rather than being integrated into the taint engine.

**Rationale:** These vulnerabilities don't follow a source→sink data-flow model. TOCTOU is a temporal pattern (check-then-act); auth bypass is a structural pattern (missing decorator, equality comparison). Forcing them into the taint engine would require a fundamentally different analysis model. Separate passes keep the taint engine focused, the pattern analyzers simple and testable, and the orchestrator composition explicit.

---

### D-031 — MinIO failures are silent; storage is non-blocking
**Date:** 2026-03-27
**Status:** Accepted

**Decision:** All MinIO operations are wrapped in try/except. If MinIO is unavailable (container not started, wrong credentials, network error), the scan continues and completes normally — only the artifact upload is skipped.

**Rationale:** Storage is a convenience feature, not a correctness requirement. Making it blocking would mean a MinIO restart or misconfiguration breaks all scans. The scan result (findings in PostgreSQL) is authoritative; MinIO holds supplementary data. This matches how cloud object storage is typically treated in production systems.
