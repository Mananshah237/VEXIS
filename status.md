# VEXIS — Build Status

**Last Updated:** 2026-03-27
**Phase:** COMPLETE — Sprint 7 + Security Hardening Done
**Overall Progress:** All planned phases shipped. Sprint 7 adds GitHub Action CI/CD integration, WeasyPrint PDF report generation, incremental scanning with file manifests, Railway deployment config + storage docs, paginated scan history dashboard, and the launch checklist + MIT license.

---

## Task Summary

### 1. WebSocket real-time scan progress ✅
- `/ws/scan/{scan_id}` endpoint in `app/api/ws/scan_ws.py`
- `ScanConnectionManager` singleton (in-memory, per-process)
- Orchestrator broadcasts at: parsing → taint_analysis → reasoning → complete/failed
- Frontend `ScanProgress.tsx` connects via WebSocket, falls back to polling if WS unavailable
- Phase indicator bar: 4 steps, active=cyan pulse, done=green checkmark

### 2. Scan input page polish (/scan/new) ✅
- Three-tab UI: Paste Code | Upload File | GitHub URL
- Paste: monospace textarea, language dropdown (Python, JS/Go disabled for Phase 3)
- Upload: drag-and-drop + click-to-browse zone
- GitHub: URL input with disclaimer about clone time
- All three POST to `/api/v1/scan` and redirect to `/scan/{id}` on success

### 3. Dashboard (/dashboard) ✅
- SWR polling every 5s: `/api/v1/stats` + `/api/v1/scans/recent`
- Stats cards: Total Scans, Total Findings, Critical count, High count
- Severity breakdown bar (stacked horizontal, proportional to finding counts)
- Recent scans list (clickable rows, status indicator dot, finding count, relative time)
- Empty state with "Start your first scan" CTA

### 4. Scan results page polish (/scan/[id]) ✅
- Scan metadata header: source, status, files parsed, duration
- ScanProgress embedded while scan is running (uses WebSocket)
- Severity breakdown bar when complete
- Findings sorted by severity (critical first)
- FindingCard: severity badge, CWE, confidence %, source:line → sink:line

### 5. Test corpus 10 samples + run_full_corpus.py ✅
- 6 samples: sqli/partial_sanitizer.py, sqli/orm_raw_fallback.py, cmdi/eval_input.py,
  path_traversal/send_file_direct.py, safe/parameterized_query.py, safe/shlex_quote.py
- `backend/tests/run_full_corpus.py` — summary table with Exp/Got/CWE/Severity/Status
- **10/10 PASSING** including both false positive checks (0 findings on safe code)

### 6. README.md ✅
- Tagline + badges, dual-engine architecture, 3-file cross-boundary SQLi example
- Scanner comparison table, quick start, 4-layer architecture diagram
- Tech stack table, vuln class table, test results, project structure, env vars, deployment

### 7. Real-world CVE validation ✅
- `backend/tests/real_world/` with 3 CVE-attributed Python snippets
- `backend/tests/run_real_world.py` — test runner
- README "Real-World CVE validation" table with NVD links

### 8. Demo walkthrough ✅
- `docs/DEMO_WALKTHROUGH.md` — 5-minute structured demo guide
- Steps 1-5: landing → scan → progress → finding detail → dashboard
- Cross-file demo section (the 3-file SQLi is now actually runnable end-to-end)

### 9. Deployment configuration ✅
- `backend/railway.toml` — Railway service config
- `frontend/railway.toml` — Railway frontend config
- `DEPLOY.md` — full Railway + Fly.io deployment guides

### 10. Cross-file (inter-procedural) taint tracking ✅
- **3/3 cross-file tests pass** (golden_test, session_poison, return_value)
- `ingestion/call_graph.py` — `ProjectCallGraph` + `CallGraphBuilder`: parses imports across files, resolves local module names to file paths, extracts function definitions with parameter names
- `taint/cross_file.py` — `CrossFileLinker`: merges per-file PDGs into a project-wide graph and injects DATA_DEP edges for three cross-file patterns:
  - Shared state stores/loads (`request.state.X`, `session["key"]`)
  - Function arg → callee parameter (call sites mapped to param names)
  - Return values → caller assignment targets
- `taint/engine.py` — `analyze_project()`: builds unified PDG → runs worklist taint on full project; `_pattern_matches()` uses word-boundary regex (fixes `input(` false positive in names like `get_user_input()`); `_dedup_paths()` pre-deduplicates before LLM to avoid redundant calls
- `api/routes/findings.py` — `ORDER BY taint_confidence DESC, confidence DESC`
- `tests/run_cross_file.py` — checks that ANY finding matches expected CWE/source_file/sink_file
- `core/orchestrator.py` — multi-file mode (>1 .py file → cross-file), `=== FILE: ===` multi-file raw_code splitting, `source_type: "directory"` support

### 12. Sprint 3 — Benchmark, Hardening & Frontend Expansion ✅

#### Semgrep benchmark harness
- `backend/tests/benchmark/__init__.py` + `semgrep_comparison.py` — 27-sample benchmark (21 corpus + 3 cross-file + 3 CVE)
- Runs Semgrep via `docker exec vexis-api-1 semgrep --config=auto --json --quiet`; outputs `tests/benchmark/results.md`
- **VEXIS TPR ~90%, Semgrep TPR ~67%; VEXIS FPR ~5%, Semgrep FPR ~10%**
- VEXIS detects all 3 cross-file cases; Semgrep detects 0 cross-file

#### Real-world repo scans
- `backend/tests/benchmark/real_repo_results.md`
- `gothinkster/flask-realworld-example-app`: 30 files, 0 findings (SQLAlchemy ORM — correct true negative)
- `pallets/flask` tutorial (flaskr): 9 files, 2 false positive SQLi (parameterized `?` misidentified by taint engine; LLM reasoning correctly says NOT exploitable)
- Known limitation documented: taint engine cannot distinguish parameterized queries from string interpolation

#### Performance & reliability hardening
- `asyncio.wait_for` wraps `_run_scan_impl()` with configurable timeout (`settings.scan_timeout_seconds`, default 600s); `scan.status = "timeout"` on expiry
- `LLMBudget` tracker (`backend/app/reasoning/budget.py`): shared counter, `try_consume()` returns False when exhausted; taint-only fallback uses `BUDGET_EXHAUSTED_REASONING` constant
- Skip files >10,000 lines — tracked in `scan.stats.skipped_large`
- Per-file parse error isolation — `stats.parse_errors` list, scan continues
- Two-level dedup in `correlation/dedup.py`: Level 1 = exact (source:line, sink:line, vuln_class); Level 2 = sink-level collapse at ≥3 paths (with `dedup_count` annotation)

#### Frontend updates
- Landing page: 3 CWE cards → 7 (added CWE-1336 SSTI, CWE-918 SSRF, CWE-502 Insecure Deserialization, CWE-79 XSS)
- Landing page: "VEXIS vs Semgrep" section added (TPR 90% vs 67%, FPR 5% vs 10%, cross-file callout)
- Finding detail: CWE ID is a clickable link to `https://cwe.mitre.org/data/definitions/{id}.html` (opens new tab)
- Scan results: taint-only banner shown when any finding has `llm_reasoning` containing "budget exhausted"

---

### 11. Sprint 2 — Vulnerability Class Expansion ✅

#### New vulnerability classes (trust_boundaries.py + test samples)
- **SSTI (CWE-1336):** sinks `render_template_string(`, `jinja2.Template(`, `Template(`; sanitizer `SandboxedEnvironment` (effective); samples `ssti/basic_template_string.py` (detects) + `ssti/safe_render_template.py` (safe)
- **SSRF (CWE-918):** sinks `requests.get/post/put/request`, `urllib.request.urlopen`, `httpx.get/post`, `session.get/post`; partial sanitizers `urlparse(`, `.hostname`; samples `ssrf/requests_get.py` (detects) + `ssrf/safe_allowlist.py` (safe - hardcoded URL)
- **Insecure Deserialization (CWE-502):** sinks `pickle.loads/load`, `yaml.load/unsafe_load`, `marshal.loads`, `shelve.open`; sanitizers `yaml.safe_load(`, `SafeLoader`; samples `deserialization/pickle_loads.py` + `deserialization/safe_yaml.py`
- **XSS (CWE-79):** sinks `Markup(`, `render_template_string(`; sanitizers `markupsafe.escape(`, `html.escape(`, `bleach.clean(`; samples `xss/reflected_basic.py` + `xss/safe_escaped.py`

#### LLM hardening (llm_client.py, pass_1_sanitizer.py, pass_2_exploit.py)
- Schema validation + retry: `_validate_schema()` checks required fields after each LLM call; retries once with field reminder; `_fill_defaults()` fills safe type-defaults on persistent failure
- Pass 1 no-sanitizer confidence: 0.8 → 0.95
- Better prompts: Pass 1 shows sanitizer details with partial flags and requires specific bypass string; Pass 2 shows full step-by-step taint path with file/line per hop and requires exact HTTP attack vector + payload

#### Test corpus expanded: 10 → 21 samples
- 14 vulnerable: SQLi×4, CMDi×3, PathTraversal×3, SSTI×1, SSRF×1, Deser×1, XSS×1
- 7 safe FP checks: parameterized, shlex_quote, render_template, hardcoded_url, yaml_safe, escaped_xss, cmdi_shlex

#### classifier.py
- Added titles for ssti, ssrf, deserialization, xss

---

### 13. Final Sprint — Chain Discovery, CI, Polish & Docs ✅

#### Section 1 — Pass 3 Chain Discovery
- `backend/app/reasoning/pass_3_chains.py` — groups medium/low findings by shared file context, sends groups of 2-4 to LLM
- LLM identifies multi-step attack chains (e.g., info-leak + gated SQLi = CRITICAL privilege escalation)
- Creates `ChainFinding` dataclasses → `Finding` ORM objects with `vuln_class="chain"` and `chain_data` JSONB column
- Test sample: `tests/vulnerable_samples/chains/info_leak_to_sqli/user_profile.py`
- Wired into orchestrator after Pass 2; broadcasts WebSocket progress at 0.88

#### Section 2 — Semgrep benchmark updated
- `tests/benchmark/semgrep_comparison.py` now includes chain test; benchmarked on 27 samples

#### Section 3 — Real repo scans
- Documented in `tests/benchmark/real_repo_results.md` (unchanged)

#### Section 4 — Reliability hardening
- Completed in Sprint 3 (unchanged)

#### Section 5 — Frontend final polish
- Landing page: Chain Discovery section (visual: medium + medium → CRITICAL chain)
- `AttackFlowGraph.tsx`: chain edges render as dashed purple lines (`#7C4DFF`), `edge_type="chain"`
- Finding detail: Chain Analysis section showing attack steps + payload sequence
- CWE badge: shows `CHAIN` label for `vuln_class="chain"` findings
- Mobile responsiveness: all grids use responsive Tailwind breakpoints (`md:`, `sm:`)

#### Section 6 — README + ARCHITECTURE.md
- `README.md`: fully rewritten with badges, benchmark table, corpus table, quick start
- `ARCHITECTURE.md`: new file, full technical deep-dive (305 lines)

#### Section 7 — CI pipeline
- `.github/workflows/ci.yml`: 3 jobs — `lint` (ruff), `test` (pytest + postgres service), `frontend-build` (npm ci && npm run build)

#### Section 8 — Final validation
- 2/2 unit tests pass (`test_taint_engine.py`)
- 21/21 corpus tests pass
- 3/3 cross-file tests pass
- Frontend builds clean
- All imports verified in container

---

### Sprint 4 — JS/TS, Framework Profiles, Async (Sprint 5) ✅

Shipped as Sprint 5. See Sprint 5 section in memory.

---

### Sprint 6 — Auth, Storage, Second-Order Injection, 6 New CWEs ✅

#### Section 1 — GitHub OAuth + JWT Auth
- `app/api/routes/auth.py` — `POST /api/v1/auth/token` (GitHub OAuth code exchange → VEXIS JWT), `POST /api/v1/auth/api-key`, `GET /auth/me`
- `app/api/deps.py` — `get_current_user()` — supports JWT Bearer and `X-VEXIS-API-Key`; anonymous fallback preserves backward compat
- `app/core/auth.py` — `create_access_token()`, `decode_token()`, `generate_api_key()`
- `app/models/user.py` — `User` ORM with `github_id`, `github_login`, `api_key`, `last_seen_at`
- `app/models/scan.py` — `user_id` column (nullable UUID); scans filtered by user when authenticated
- `app/core/rate_limiter.py` — Redis-based free tier: 3 scans/day (`rate:{user_id}:{date}`, 24h TTL); anonymous always allowed
- `app/config.py` — `github_client_id`, `github_client_secret`, `jwt_secret`, `jwt_expire_minutes`
- Frontend: `next-auth` GitHub provider, `src/app/api/auth/[...nextauth]/route.ts`, `src/lib/auth.ts`
- Frontend: `src/middleware.ts` — protects `/dashboard`, `/scan/*`, `/reports`, `/settings`; landing stays public
- Frontend: `NavBar.tsx` — sign in / sign out with GitHub avatar; `src/app/settings/page.tsx` — API key gen

#### Section 2 — MinIO Persistent Storage
- `app/core/storage.py` — `ensure_buckets()`, `upload_code_snapshot()`, `upload_artifact()`, `get_signed_url()`, `list_objects()`
- Buckets: `code-snapshots`, `scan-artifacts`, `reports`
- Orchestrator uploads code snapshot + taint_summary artifact after each scan
- `GET /api/v1/scan/{id}/download-code` — presigned URL to code snapshot
- `GET /api/v1/scan/{id}/artifacts` — presigned URLs for all scan artifacts
- `docker-compose.yml` — `minio` service (port 9000/9001)

#### Section 3 — Second-Order Injection (Experimental)
- `app/analysis/second_order.py` — `analyze_second_order()`: scans for HTTP-source → parameterized INSERT → SELECT → dangerous sink chains
- Detects stored XSS and second-order SQLi even when the INSERT is parameterized (looks safe)
- Test samples: `tests/vulnerable_samples/second_order/stored_xss.py`, `stored_sqli.py`
- Wired into orchestrator after main taint/LLM passes

#### Section 4 — 6 New Vulnerability Classes (13 total)
- **CWE-601 Open Redirect** — `redirect(TAINTED)` sinks; `.startswith("/")` sanitizer
- **CWE-117 Log Injection** — `logging.*()`, `logger.*()`, `print()` sinks; newline-strip sanitizer
- **CWE-90 LDAP Injection** — `ldap.search_s(TAINTED)` sinks; `escape_filter_chars()` sanitizer
- **CWE-611 XXE** — `ET.parse()`, `etree.parse()`, `minidom.parse()` sinks; `defusedxml.*` sanitizer
- **CWE-362 Race Condition/TOCTOU** — `app/analysis/race_detector.py` pattern-based (check-then-act on filesystem/balance)
- **CWE-287 Auth Bypass** — `app/analysis/auth_analyzer.py` pattern-based (missing auth decorator, timing attack `==`, client-controlled role)
- `EXTRA_SINKS` + `EXTRA_SANITIZERS` in `trust_boundaries.py` loaded into taint engine at init
- `classifier.py` updated with titles for all new classes
- Test samples: `redirect/`, `log_injection/`, `ldap/`, `xxe/`, `race/`, `auth/` (vulnerable + safe for each)

#### Section 5 — Full Validation (45-sample corpus)
- `tests/run_full_corpus.py` — 45 samples total
  - 14 vulnerable Python + 7 safe FP checks + 10 JS + 1 context sanitizer + 2 second-order + 11 new-CWE tests
- Semgrep benchmark updated to include all Sprint 6 samples (45 VEXIS samples + Semgrep comparison)
- Expected: VEXIS detects race condition and auth bypass (pattern analysis); Semgrep cannot

---

### Security Hardening (pre-release) ✅

#### Vulnerabilities fixed
- **SSRF prevention** — `git_ops.py`: URL allowlist (GitHub/GitLab/Bitbucket HTTPS only), regex blocks `..` and shell-injection chars
- **Hardcoded secrets removed** — `config.py`: `jwt_secret` and `minio_secret_key` now default to `""` (app must set env vars); `.env.example` updated with `CHANGE_ME` markers
- **Auth added to all sensitive routes** — `triage.py`, `findings.py` (`get_finding`), `scan.py` (`download_code_snapshot`, `list_scan_artifacts`) now check scan ownership via `get_current_user`
- **CORS hardened** — `main.py`: explicit allow list (`GET POST PUT PATCH DELETE OPTIONS` + `Authorization Content-Type Accept X-Requested-With`), removed wildcard `*`
- **Input validation** — `schemas.py` `TriageRequest`: `status` validated against allowlist enum, `notes` capped at 2 000 chars
- **docker-compose.yml** — `MINIO_SECRET_KEY` uses `${MINIO_SECRET_KEY:?}` (required env var, fails fast if not set); log level `DEBUG` → `INFO`

---

### Sprint 7 — GitHub Action, PDF Reports, Incremental Scanning, Deploy, History UI, Launch ✅

#### Section 1 — GitHub Action
- `action/action.yml` — Docker-based action: inputs (api-url, api-key, severity-threshold, scan-path, languages, timeout), outputs (scan-id, findings-count, critical-count, high-count, report-url)
- `action/Dockerfile` — `python:3.12-slim` + `httpx`
- `action/entrypoint.py` — collects source files, submits scan, polls, emits `::error file=,line=::` annotations for high/critical, `::warning` for others, exits 1 when findings exceed threshold
- `action/README.md` — usage YAML, inputs/outputs tables, all detected CWE IDs, API key setup

#### Section 2 — PDF Report Generation
- `weasyprint>=62.0` added to `backend/pyproject.toml`
- `backend/Dockerfile` — apt-get installs `libpango`, `libpangoft2`, `libgdk-pixbuf-2.0`, `libcairo2`, `fontconfig`, `fonts-liberation`
- `backend/app/reporting/templates/report_base.html` — A4 CSS base (badges, callouts, taint path styles)
- `backend/app/reporting/templates/report_full.html` — full Jinja2 template: cover page, executive summary, findings detail (taint path, PoC, AI analysis, chain section), appendix (OWASP mapping, glossary)
- `backend/app/reporting/pdf_builder.py` — `build_pdf(scan, findings) -> bytes` (WeasyPrint), `build_html(scan, findings) -> str` (testing)
- `backend/app/api/routes/reports.py` — `GET /api/v1/report/{scan_id}` (PDF, cached in MinIO), `GET /api/v1/report/{scan_id}/html` (preview)
- Frontend: "Download PDF Report" button on scan results page

#### Section 3 — Incremental Scanning
- `backend/app/core/incremental.py` — `compute_manifest()` (SHA-256 per file), `changed_files()`, `save_manifest()` (to MinIO), `get_changed_files_for_scan()` (compare to previous scan)
- `backend/app/models/schemas.py` — `ScanConfig.incremental: bool = False`
- Orchestrator: if `config.incremental=True`, loads previous manifest, filters file list to changed/new only; always saves new manifest for future comparison
- `GET /api/v1/scan/{id}/compare/{other_id}` — returns new/resolved/unchanged findings
- Frontend: "Re-scan (incremental)" button submits new scan with `incremental: true`

#### Section 4 — Railway Deployment Config
- `DEPLOY.md` — added S3/R2/MinIO storage options section, auth env vars, CORS env var, full env var reference table updated

#### Section 5 — Scan History UI
- `backend/app/api/routes/stats.py` — `GET /api/v1/scans/recent` now supports `page`, `limit`, `status`, `min_severity` query params; returns `total`, `pages`, `max_severity` per scan
- Frontend `dashboard/page.tsx` — paginated scan history (15/page), status filter dropdown, severity filter dropdown, max severity dot indicator per row

#### Section 6 — Final Launch
- `LAUNCH_CHECKLIST.md` — infrastructure, auth, security, core scan, PDF, incremental, GitHub Action, docs, smoke test
- `LICENSE` — MIT license

---

## E2E Test Results

### Quick smoke test (4/4)
```bash
python -X utf8 backend/tests/run_e2e.py
```
```
[PASS] sqli_fstring    [CRITICAL] CWE-89
[PASS] sqli_concat     [CRITICAL] CWE-89
[PASS] cmdi            [CRITICAL] CWE-78
[PASS] path_trav       [HIGH]     CWE-22
4/4 passed
```

### Cross-file taint suite (3/3)
```bash
python -X utf8 backend/tests/run_cross_file.py
```
```
Test                   CWE        Src file           Sink file          Status
golden_test            CWE-89     rate_limiter.py    logger.py          PASS
session_poison         CWE-78     login.py           admin.py           PASS
return_value           CWE-78     utils.py           handler.py         PASS
3/3 passed
```

### Full Corpus (45 samples — Sprint 6)
```bash
python -X utf8 backend/tests/run_full_corpus.py
```
Expected results (45 samples):
- 14 Python vulnerable → 1 finding each with correct CWE
- 7 Python safe → 0 findings
- 10 JS samples → correct CWE / 0 findings
- 1 context sanitizer (escape→SQL finds SQLi, not XSS)
- 2 second-order samples → detected via second_order analyzer
- 11 new-CWE samples → 6 detected, 5 safe=0 findings

### Real-World CVE Validation
```bash
python -X utf8 backend/tests/run_real_world.py
```
```
CVE               Expected CWE   Description
CVE-2022-34265    CWE-89         Django Trunc/Extract SQL injection
CVE-2023-30553    CWE-78         Archery db_name command injection
CVE-2023-47890    CWE-22         pyLoad pack_folder path traversal
```

---

## Sprint 6 Commands

```bash
# Full corpus (45 samples)
python -X utf8 backend/tests/run_full_corpus.py

# Semgrep comparison benchmark (Sprint 6 — 41 samples)
python -X utf8 backend/tests/benchmark/semgrep_comparison.py

# Real-world repo scan results
cat backend/tests/benchmark/real_repo_results.md

# Run CI pipeline locally
# lint
uv run ruff check backend/app/
# unit tests
uv run pytest backend/tests/test_taint_engine.py -v
# frontend build
cd frontend && npm ci && npm run build
```

---

## Known Issues / Limitations

1. **sqli_partial_sanitizer severity = LOW** — `.replace("'", "")` reduces taint confidence (base=0.5 for PARTIALLY_SANITIZED). Finding IS detected, but severity is conservative. Acceptable for MVP.

2. **Hot-reload kills in-flight scans** — uvicorn --reload restarts on .py file changes, killing BackgroundTasks mid-scan. Don't edit code while a scan is running.

3. **Second-order injection is experimental** — Pattern-based heuristic (HTTP source within 8 lines of INSERT + SELECT + dangerous sink). Can miss cases where taint flows through many intermediate steps. Documented as experimental in outputs.

7. **Taint engine misidentifies parameterized `?` queries** — `cursor.execute("SELECT ... WHERE x = ?", (val,))` can be flagged as SQLi because the `?` pattern matches the taint sink regex. LLM pass 2 correctly marks these NOT exploitable, but they appear as false positives in taint-only mode. Documented in `real_repo_results.md` (flaskr scan).

6. **SSRF safe detection requires hardcoded URL pattern** — The taint engine cannot evaluate allowlist logic at runtime. The `urlparse(` sanitizer is marked partial because `urlparse(url)` followed by `requests.get(url)` still passes `url` directly to the SSRF sink without the urlparse node appearing on the taint path. Safe SSRF code must use a hardcoded URL constant (no taint source) to produce 0 findings.

4. **Cross-file taint: class attributes** — `self.data = tainted` in one method → `self.data` in another method is not yet tracked. Shared state tracking handles `request.state.*` and `session[*]` but not arbitrary class attribute stores.

5. **NEXT_PUBLIC_ vars baked at build time** — In Railway/Fly.io, must set before build then redeploy. Change API URL requires frontend rebuild.

---

## Services

| Service | URL |
|---------|-----|
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Frontend | http://localhost:3000 |
| PostgreSQL | localhost:5432 (vexis/vexis) |
| Redis | localhost:6379 |

## Quick Commands

```bash
# Start everything
docker compose up -d

# Quick E2E (4 samples)
python -X utf8 backend/tests/run_e2e.py

# Cross-file taint suite (3 scenarios)
python -X utf8 backend/tests/run_cross_file.py

# Full corpus (21 samples)
python -X utf8 backend/tests/run_full_corpus.py

# Real-world CVE validation
python -X utf8 backend/tests/run_real_world.py

# View API logs
docker compose logs -f api

# Reset DB
docker compose down -v && docker compose up -d
```
