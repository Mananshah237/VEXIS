# VEXIS — Project Status

Last updated: 2026-06-18

---

## 2026-06-18 — Security hardening pass

Worked through `SECURITY_AUDIT.md`. Done:

- **Auth is now mandatory:** `deps.py` no longer downgrades invalid/missing
  credentials to an anonymous user (bad token → 401); the Next.js auth middleware
  matcher (`frontend/src/middleware.ts`) is re-enabled to protect app routes.
- **Anon data exposure / IDOR closed:** scans require auth to create and every
  read/list/download is owner-scoped — previously `user_id NULL` scans were
  world-readable.
- **JWT secret:** required from env with a startup guard (no empty/default boot).
  Weak dev secrets pulled out of `.env`/`docker-compose.yml`.
- **Secrets at rest:** GitHub OAuth token + provider API keys are now encrypted in
  the `users` table (`app/core/crypto.py`, Fernet via `VEXIS_ENCRYPTION_KEY`).
- **Rate limiting** now covers the anonymous path and fails closed.
- **Migrations/DR:** added the initial Alembic migration
  (`alembic/versions/0001_initial_schema`); GDPR erasure via `DELETE /auth/me`
  (cascades findings → scans → user + MinIO objects).
- **Tests + CI:** taint/sample + API tests — **33 passing**; CI runs the fuller
  suite + SCA. `docs/DISASTER_RECOVERY.md` and `docs/DATA_RETENTION.md` added.

**Rotate:** the live Gemini key that was in `.env` (git-ignored, not in history) —
rotate it in the provider console. Set a fresh `JWT_SECRET` + `VEXIS_ENCRYPTION_KEY`.

---

## 2026-06-16 — Full-stack auth exchange (frontend ↔ backend) + autofix UI

The frontend (NextAuth) and backend (own JWT) auth systems didn't talk: API calls
were anonymous and the GitHub token never reached the backend. Now coherent end to end:

- **Backend `/auth/token`** accepts the NextAuth GitHub access token (not just an
  OAuth `code`), upserts the user, **stores the GitHub token** on the user, returns
  a VEXIS JWT.
- **`get_current_user`** (deps) now loads the user and surfaces `github_token`.
- **NextAuth `jwt` callback** exchanges the GitHub token → VEXIS JWT and puts it in
  the session (`vexisToken`); server-side fetch uses `BACKEND_INTERNAL_URL`
  (added to docker-compose as `http://api:8000`) so it works inside Docker.
- **`api.ts`** sends `Authorization: Bearer <vexisToken>` on every call (+ new
  `generateAutofix` / `openPullRequest` helpers); scan creation + finding page are
  now authenticated, so **scans are owned** and ownership checks work.
- **Private-repo clone**: `clone_repo(url, token)` does a fresh authenticated clone
  (bypassing the shared cache so the token never lands in a cache key/log);
  orchestrator passes the scan owner's stored token.
- **PR endpoint** uses the stored token automatically (token no longer required in
  the request body).
- **Finding page**: added the **Suggested Fix** panel — Generate Fix → colored diff +
  explanation → Open Pull Request → View PR link.
- **Schema**: `findings.autofix` and `users.github_token` added to the startup
  auto-migration list (`_SCHEMA_MIGRATIONS`), so existing DBs get them on boot.

Not verifiable here: frontend not typechecked/built (node_modules absent) and the
PR/private-clone flow needs a live GitHub token + repo to confirm end to end.

---

## 2026-06-16 — Autofix + PR generation, and GitHub sign-in / repo picker fixes

### Autofix + PR generation (new)
- `app/exploit/autofix_generator.py` — LLM produces a remediated version of the
  vulnerable code + a unified diff + explanation (mirrors the exploit-script
  generator; per-vuln-class fallback hints when no LLM).
- `app/exploit/pr_generator.py` — GitHub REST API: fetch file → create branch →
  commit the fix → open a PR (needs the user's token with `repo` scope).
- `app/api/routes/autofix.py` (registered in `main.py`):
  - `POST /api/v1/finding/{id}/autofix/generate` — generate + store the fix.
  - `GET  /api/v1/finding/{id}/autofix` — return it.
  - `POST /api/v1/finding/{id}/pr` — open a fix PR (fixes the whole file, opens PR).
- `Finding.autofix` JSON column added (patched_code/diff/explanation/summary[/pr_url]).
  NOTE: dev uses create_all(); existing DBs need an Alembic migration for this column.

### GitHub sign-in / repo selection fixes
- `frontend/src/lib/auth.ts` — GitHub provider now requests scopes
  `read:user user:email repo` (was none → token couldn't list repos or open PRs).
  Existing users must re-authorize to pick up the new scope.
- `frontend/src/app/api/github/repos/route.ts` — new server route listing the
  user's repos with their session token (token stays server-side).
- `frontend/src/app/scan/new/page.tsx` — added a searchable **repo picker** in the
  GitHub tab (when signed in); enabled all 10 languages in the dropdown (was
  Python only, JS/Go marked "Phase 2 disabled"); updated copy.

Pending/untested against live GitHub: the PR flow needs a real token + repo to
verify end-to-end; repo-relative path derivation from `sink_file` is best-effort
(strips clone prefix up to the repo name).

---

## 2026-06-16 — Full language set (Go, Ruby, C/C++, Rust, Bash) + language-scoped matching

Added five more languages on top of Java, so VEXIS now analyzes:
**Python, JS/TS, Java, Go, Ruby, C, C++, Rust, Bash.**

- Grammars registered in `parser.py` (`.go .rb .c .h .cpp .cc .cxx .hpp .rs .sh .bash`);
  deps added to `pyproject.toml`; extensions added to `orchestrator.py` scan discovery.
- `pdg_builder.py` teaches each language's AST node types + variable def/use/call
  extraction (Go short_var_declaration, C declarator chains, Rust let_declaration,
  Bash variable_assignment/$-expansions, Ruby assignment/call, etc.).
- `trust_boundaries.py` adds `<LANG>_TAINT_SOURCES/SINKS/SANITIZERS` per language,
  incl. a new **buffer_overflow** vuln class for C/C++ (strcpy/strcat/sprintf/gets).

### Important fix — language-scoped pattern matching
Matching every language's patterns against every file caused cross-language
collisions (Python's FastAPI `Query(` source matched Go's `db.Query(` sink → false
positive). Fixed properly:
- `PDGNode` now carries `language`; the cross-file linker preserves it.
- `TaintEngine` matches only the node's language patterns (+ framework extras),
  via `_lists_for()` / `_groups`.
- `graph_folder` pattern set now includes all languages so sanitizer nodes in any
  language are treated as anchors (not folded away).

Tests: new `tests/test_polyglot_samples.py` (14 tests across Go/Ruby/C/Rust/Bash)
+ `tests/test_java_samples.py` (8) + existing engine/sample tests = **32 passed**.

Remaining from the original wishlist: HTML & Markdown don't fit a taint/data-flow
model (no sources→sinks) — they'd need a separate pattern-scanner engine; COBOL
needs a maintained tree-sitter grammar + a test corpus. Both deferred deliberately.

---

## 2026-06-15 — Java language support added

VEXIS now analyzes **Java** in addition to Python and JS/TS (first new language
of the multi-language expansion).

Wired in five places (see `app/ingestion/languages/java.py` for the full recipe):
- `parser.py` — tree-sitter-java grammar registered (`.java` extension).
- `pdg_builder.py` — Java AST node types added to the classifier and to
  variable def/use/call extraction (`local_variable_declaration`,
  `method_invocation`, `method_declaration`, etc.).
- `trust_boundaries.py` — `JAVA_TAINT_SOURCES / JAVA_TAINT_SINKS / JAVA_SANITIZERS`
  (Servlet + Spring sources; JDBC/Runtime/File/response/SSRF/deser sinks;
  PreparedStatement, numeric casts, FilenameUtils, HTML encoders as CCSM sanitizers).
- `taint/engine.py` — Java lists concatenated into the engine.
- `core/orchestrator.py` + `pyproject.toml` — `.java` added to scan discovery and
  `tree-sitter-java` to dependencies.

Tests: new `tests/test_java_samples.py` — **8 Java tests** (SQLi, command
injection, path traversal, reflected XSS — vulnerable detected + safe cleared).
Full analysis suite (Java + existing): **19 passed**. Corpus under
`tests/vulnerable_samples/{sqli,cmdi,path_traversal,xss}/*.java`.

Next languages (mechanical, follow java.py recipe): Go, Ruby, C/C++, Rust.
Deferred cleanup: move each language's (grammar, node-map, patterns) behind a
`LanguageProfile` registry; consolidate the two extension maps
(`parser._EXT_MAP` and `core/language_detect.py`).

---

## Current state: Sprint 10 complete

All features shipped and tested. System is production-ready for self-hosted deployment.

---

## What's built

### Core engine
- Tree-sitter parsing: Python, JS, TS, TSX, JSX
- PDG builder (NetworkX DiGraph): DATA_DEP, CONTROL_DEP, CALL, RETURN edge types
- **Graph Folding**: passthrough chain collapse before taint traversal (`app/ingestion/graph_folder.py`)
- Cross-file taint analysis (CallGraphBuilder + CrossFileLinker)
- Framework detection: Flask, Django, FastAPI, Express

### CCSM — Continuous Constraint Sanitizer Model
- 60 sanitizer patterns with calibrated `constraint_power` (0.0–1.0) replacing boolean `is_partial`
- `danger_score` propagation: `new_danger = current * (1 - constraint_power)`
- Context-sensitive at sinks: `html.escape()` effective for XSS (cp=0.90), 0 constraint for SQLi
- Early termination: paths with danger < `VEXIS_DANGER_THRESHOLD` (default 0.15) pruned
- `taint_confidence` = effective danger score at the specific sink type

### Vulnerability classes (15)
| CWE | Class |
|-----|-------|
| CWE-89 | SQL Injection |
| CWE-78 | Command Injection |
| CWE-22 | Path Traversal |
| CWE-1336 | SSTI |
| CWE-918 | SSRF |
| CWE-502 | Insecure Deserialization |
| CWE-79 | XSS |
| CWE-601 | Open Redirect |
| CWE-117 | Log Injection |
| CWE-90 | LDAP Injection |
| CWE-611 | XXE |
| CWE-362 | Race Condition / TOCTOU |
| CWE-287 | Auth Bypass |
| — | Second-Order Injection |
| — | Attack Chain (Pass 3) |

### AI Reasoning
- **Pass 1**: Sanitizer bypass evaluation
- **Pass 2**: Exploit feasibility + payload generation
- **Pass 3**: Chain discovery (low+low → CRITICAL)
- **Pass 4**: Business logic discovery (LLM-driven, no taint engine required)
- LLM client: Gemini → Ollama → Anthropic fallback
- LLM budget: configurable per-scan call limit with taint-only fallback
- JSON recovery: triple-quoted Python strings in Ollama JSON handled via regex extraction

### Exploit generation
- Exploit script generator: LLM produces full runnable Python PoC per finding
- `findings.exploit_script` column stores the script (TEXT)
- `GET /api/v1/finding/{id}/exploit` — download as `.py`
- Fallback to template PoC if LLM fails or returns empty script (`or base_script` pattern)

### Infrastructure
- PostgreSQL 16 + SQLAlchemy async
- Redis + Celery async scan workers
- MinIO object storage (code snapshots, artifacts, PDF reports)
- Presigned URL rewriting: `MINIO_PUBLIC_ENDPOINT` for browser-accessible URLs
- GitHub OAuth + JWT + API key auth (multi-tenant)
- Rate limiting: 3 scans/day free tier (Redis counter)
- Incremental scanning: SHA-256 file manifest per scan
- PDF reports: WeasyPrint (cover + exec summary + per-finding + OWASP map + glossary)
- GitHub Action: `vexis-action@v1` for CI/CD integration
- WebSocket real-time progress broadcast
- Semgrep differential analysis (VEXIS-only / overlap / Semgrep-only)

### Frontend
- Next.js 14 (App Router) + Tailwind CSS
- Landing page, Dashboard, Scan results, Finding detail
- **Inline exploit scripts on finding cards**: `⚡ Exploit` badge, expand/copy/download
- D3.js attack flow graph (force-directed, chain edges as dashed purple)
- ScanProgress WebSocket consumer
- Dark theme, monospace code blocks

---

## Test results

### Quick smoke test (4/4)
```
[PASS] sqli_fstring    [CRITICAL] CWE-89  taint_confidence=1.00
[PASS] sqli_concat     [CRITICAL] CWE-89  taint_confidence=1.00
[PASS] cmdi            [CRITICAL] CWE-78  taint_confidence=1.00
[PASS] path_trav       [HIGH]     CWE-22  taint_confidence=1.00
```

### Full corpus: 45/45 passed
All CCSM false-positive checks pass (parameterized queries, shlex.quote, html.escape → 0 findings).

### Cross-file: 3/3 passed

### Real-world CVE validation: 3/3 detected

### Real-world benchmark repos
| Repo | Time | Findings | Notes |
|------|------|----------|-------|
| we45/Vulnerable-Flask-App | 61s | 7 | All true positives |
| ajinabraham/nodejsscan | ~90s | 4 | 0 false positives from library code |

---

## Security patches (Sprint 10)

### Arbitrary local directory read / SSRF via scan source — fixed
**Severity:** Critical
**Root cause:** `POST /api/v1/scan` accepted `source_type: "directory"` and `source_type: "file_upload"` with arbitrary server-side paths. The orchestrator would scan `/etc`, `/app`, or any readable path and expose source code snippets in findings.

**Fix:**
- `scan.py`: Added allowlist guard at the top of `create_scan` — only `github_url` and `raw_code` are accepted. Any other `source_type` is rejected with HTTP 400.
- `cli/vexis_cli.py`: CLI no longer sends local paths to the server. Local files/directories are now bundled into a `raw_code` payload (using `=== FILE: name ===` separators) before sending — identical to how the GitHub Action works. A 2 MB character cap prevents oversized payloads.

**Verification:**
```bash
# Must return 400
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"source_type":"directory","source":"/etc"}' | python3 -m json.tool

# Expected: {"detail": "Invalid source_type. Only 'github_url' and 'raw_code' are accepted..."}
```

---

## Security patches (Sprint 9)

### IDOR / unauthenticated access bypass — fixed
**Severity:** Critical
**Root cause:** All ownership checks used `if current_user and scan.user_id and ...` — when `current_user` is `None` (unauthenticated), the entire condition short-circuits to `False` and access is granted unconditionally.
**Impact:** Unauthenticated attackers could read private scans, findings, exploit scripts, PDF reports, and mutate triage status on any user's data.

**Fix applied across 12 endpoints in 7 files:**

| File | Endpoints fixed |
|------|----------------|
| `scan.py` | `get_scan`, `download_code_snapshot`, `compare_scans`, `list_scan_artifacts` |
| `findings.py` | `list_findings`, `get_finding` |
| `triage.py` | `triage_finding` |
| `exploit.py` | `download_exploit`, `generate_exploit` |
| `reports.py` | `_load_scan_and_findings` (shared helper) |
| `differential.py` | `get_differential` |
| `stats.py` | `get_stats`, `get_recent_scans` (added `get_current_user` dep + user-scoped queries) |

**New invariant:** A scan with `user_id IS NOT NULL` can only be accessed by the authenticated user whose `id` matches. Anonymous scans (`user_id IS NULL`) are publicly accessible. Unauthenticated users see only anonymous scans in `/scans/recent` and `/stats`.

### PDF download — fixed
Presigned MinIO URL was generated for non-existent objects, causing 302→404. Added `object_exists()` check before redirect; first request now builds and streams PDF directly.

### Frontend auth
- GitHub OAuth is optional — app works fully without `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` set
- All routes open to guests (middleware matcher set to `[]`)
- `NEXTAUTH_SECRET` auto-seeded with a dev default if not set
- Exploit script truncation fixed: Ollama `num_predict` raised from 512 → 2048; added minimum-length guard to fall back to template on truncated LLM output

---

## Known limitations

1. **Graph folding latency vs benefit**: real PDGs use dual STATEMENT+ASSIGNMENT nodes per line which prevents most passthrough folding. The optimization activates on simpler chains; overhead is O(n) per PDG which is small.
2. **conn.execute not recognized**: sink patterns cover `cursor.execute`, `db.execute` etc. but not arbitrary variable names like `conn.execute`. User-named DB connections need explicit sink patterns.
3. **Taint path confidence**: fully unsanitized paths get `taint_confidence=1.0`; the finding `confidence` (combined) may be slightly lower due to LLM uncertainty.

---

## Environment variables

```bash
GOOGLE_API_KEY=...
ANTHROPIC_API_KEY=...               # optional
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://redis:6379
OLLAMA_BASE_URL=http://host.docker.internal:11434
MINIO_ENDPOINT=minio:9000
MINIO_PUBLIC_ENDPOINT=http://localhost:9000
VEXIS_SCAN_TIMEOUT_SECONDS=600
VEXIS_MAX_LLM_CALLS_PER_SCAN=100
VEXIS_DANGER_THRESHOLD=0.15
```

---

## Recent commits

```
(Sprint 10)
fix: SSRF/local path scan via source_type allowlist; CLI bundles local files as raw_code
fix: harden .gitignore — backend/.env, .claude/ excluded; merge main+master
(Sprint 9)
fix: critical IDOR auth bypass across all API endpoints; PDF cache; exploit truncation
(Sprint 8)
3ddfcf3  feat: inline exploit scripts on finding cards; update all docs to Sprint 8
357a893  feat: CCSM continuous sanitizer scoring, Graph Folding, exploit/presigned URL fixes
946ffc1  feat: wire exploit gen, Pass 4, and Semgrep into scan pipeline
90e9368  feat: differential Semgrep analysis
402aa55  feat: business logic discovery mode (Pass 4)
0de6464  feat: auto-generated exploit scripts per finding
5668b8c  fix: exclude vendored/minified files from scanning
```
