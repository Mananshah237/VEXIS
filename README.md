# VEXIS — Vulnerability EXploration & Inference System

> Every other scanner matches patterns. VEXIS **reasons**.

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green?logo=fastapi)
![Next.js 14](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![Tree-sitter](https://img.shields.io/badge/Tree--sitter-Python%2FJS%2FTS-orange)
![D3.js](https://img.shields.io/badge/D3.js-visualization-F7DF1E?logo=d3.js)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql)
![Celery](https://img.shields.io/badge/Celery-async_scanning-37814A?logo=celery)
![13 CWE Classes](https://img.shields.io/badge/13_CWE_Classes-detected-red)
![45 Test Cases](https://img.shields.io/badge/45_Test_Cases-passing-brightgreen)
![GitHub OAuth](https://img.shields.io/badge/Auth-GitHub_OAuth-black?logo=github)
![MinIO](https://img.shields.io/badge/Storage-MinIO-red?logo=minio)
![PDF Reports](https://img.shields.io/badge/Reports-PDF_WeasyPrint-blueviolet)
![GitHub Action](https://img.shields.io/badge/CI-GitHub_Action-2088FF?logo=github-actions)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What makes VEXIS different

- **Cross-file taint tracking.** VEXIS follows tainted data across function call boundaries — something no pattern-matching scanner does. A header value that enters in `middleware.py`, passes through `handlers.py`, and causes SQL injection in `logger.py` is caught. Semgrep misses it entirely.

- **LLM-powered sanitizer reasoning.** When a sanitizer exists between source and sink, VEXIS doesn't just mark it "safe" — it asks an LLM whether the sanitizer can be bypassed (and how). Real sanitizers reduce findings. Ineffective ones are flagged with bypass payloads.

- **Attack chain discovery.** Pass 3 looks at multiple individually-medium findings and identifies when they combine into a critical attack. An info-leak (medium) + a gated privilege escalation (medium) = CRITICAL privilege escalation chain. No other open-source tool does this.

- **JavaScript & TypeScript support.** Tree-sitter grammars for JS/JSX/TS/TSX. Express, Node.js, and JS-specific sources (req.params, req.body), sinks (eval, connection.query\`…\`, innerHTML), and sanitizers (DOMPurify, execFile) are all first-class.

- **Framework-aware analysis.** Auto-detects Flask, Django, FastAPI, and Express. Loads framework-specific source/sink/sanitizer profiles — e.g., Django's `mark_safe()` is flagged as an XSS sink, `.raw()` as SQLi. Flask's `render_template_string` is a SSTI sink; `render_template` is safe.

- **Context-sensitive sanitizers.** `html.escape()` prevents XSS but NOT SQLi. VEXIS tracks which sanitizer is effective for which vulnerability class — so `escape(q)` in an f-string SQL query still fires CWE-89 even though the XSS path is suppressed.

- **Second-order injection detection.** VEXIS tracks HTTP input that flows through a parameterized INSERT (which looks safe to pattern scanners) and surfaces again in a SELECT result used unsafely — stored XSS and second-order SQLi. This is experimental but unique in open-source tooling.

- **GitHub OAuth + API key auth.** Multi-tenant with per-user scan isolation, rate limiting (3 scans/day free tier), and API key generation for programmatic access.

- **MinIO persistent storage.** Code snapshots, taint artifacts, and reports stored in object storage. Signed download URLs for every scan.

- **PDF report generation.** One-click PDF export via WeasyPrint: cover page with risk score gauge, executive summary, per-finding taint paths + PoC + AI analysis, OWASP mapping, and glossary. Reports cached in MinIO for fast repeated downloads.

- **GitHub Action.** Drop-in CI/CD integration: `uses: mananshah237/vexis-action@v1` submits your repo on every push/PR, blocks merges on high+ findings, and annotates the exact vulnerable lines inline on GitHub pull requests.

- **Incremental scanning.** SHA-256 file manifest stored per scan. Re-scan with `incremental: true` to analyze only changed files — 10× faster on large codebases where only a few files changed.

---

## VEXIS vs Semgrep

Benchmarked on 41 samples: 21 single-file corpus + 3 cross-file scenarios + 3 real-world CVE patterns + 14 Sprint 6 new-CWE/second-order samples.

| Metric | VEXIS | Semgrep |
|--------|-------|---------|
| True positive rate | 90% | 67% |
| False positive rate | 5% | 10% |
| Cross-file detection | ✓ Yes | ✗ No |
| Chain discovery | ✓ Yes | ✗ No |
| Second-order injection | ✓ Yes | ✗ No |
| Race condition / TOCTOU | ✓ Yes | ✗ No |
| Auth bypass detection | ✓ Yes | ✗ No |
| LLM reasoning | ✓ Yes | ✗ No |
| PoC generation | ✓ Yes | ✗ No |

VEXIS uniquely detected all 3 cross-file vulnerabilities, all chain attacks, all second-order injections, and all race condition / auth bypass patterns — Semgrep produced zero findings for all of these.

---

## The 3-file example

Every pattern-matching scanner misses this:

```python
# middleware/rate_limiter.py
def check_rate_limit(request):
    client_id = request.headers.get("X-Client-ID")
    request.state.client_id = client_id  # stored in "trusted" state
```

```python
# handlers/search.py
def search(request):
    query = request.query_params.get("q")
    safe = query.replace("'", "")  # search query IS sanitized (decoy)
    log_search(request.state.client_id, safe)  # client_id is NOT sanitized
```

```python
# utils/logger.py
def log_search(client_id, q):
    db.execute(f"INSERT INTO log (client_id) VALUES ('{client_id}')")
    #          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #          SQL INJECTION via X-Client-ID header
```

VEXIS result: **CWE-89 CRITICAL** · Source: `rate_limiter.py:2` · Sink: `logger.py:3` · Payload: `'; DROP TABLE users;--`

---

## Quick start

```bash
git clone https://github.com/you/vexis
cd vexis

# Add your Gemini API key
echo "GOOGLE_API_KEY=your_key_here" >> backend/.env

# Start everything
docker compose up --build

# Open browser
open http://localhost:3000
```

**Multi-file scan via API** (use `=== FILE: name.py ===` separators):

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "raw_code",
    "source": "# === FILE: rate_limiter.py ===\ndef check_rate_limit(request):\n    client_id = request.headers.get(\"X-Client-ID\")\n    request.state.client_id = client_id\n\n# === FILE: logger.py ===\nimport sqlite3\ndef log_search(client_id, query):\n    db = sqlite3.connect(\"app.db\")\n    db.execute(f\"INSERT INTO log (client_id) VALUES (\'{client_id}\')\") "
  }' | python3 -m json.tool
```

**Requirements:** Docker + Docker Compose. No other local dependencies.

---

## Detected vulnerability classes

| CWE | Class | Description |
|-----|-------|-------------|
| CWE-89 | SQL Injection | f-strings, concatenation, ORM raw queries |
| CWE-78 | Command Injection | subprocess shell=True, os.system, eval |
| CWE-22 | Path Traversal | os.path.join bypass, send_file, open() |
| CWE-1336 | SSTI | render_template_string, Jinja2 Template() |
| CWE-918 | SSRF | requests.get, httpx, urllib with user input |
| CWE-502 | Insecure Deserialization | pickle.loads, yaml.load, marshal |
| CWE-79 | XSS | Markup(), render_template_string with user data |
| CWE-601 | Open Redirect | redirect(user_input), Location header |
| CWE-117 | Log Injection | logging.*, logger.*, print() with user data |
| CWE-90 | LDAP Injection | ldap.search_s, ldap3 Connection.search |
| CWE-611 | XXE | ET.parse, etree.parse, minidom.parse |
| CWE-362 | Race Condition / TOCTOU | os.path.exists + os.remove without locking |
| CWE-287 | Auth Bypass | missing decorator, timing attack ==, client-controlled role |
| — | Second-Order Injection | DB write→read→sink across route handlers (experimental) |
| — | Attack Chain | Multi-path chains discovered by Pass 3 |

---

## Test corpus results

```
Sample                              Exp  Got  CWE        Severity   Status
sqli_fstring                          1    1  CWE-89     CRITICAL   PASS
sqli_concat                           1    1  CWE-89     CRITICAL   PASS
sqli_partial_sanitizer                1    1  CWE-89     LOW        PASS
sqli_orm_raw_fallback                 1    1  CWE-89     CRITICAL   PASS
cmdi_subprocess                       1    1  CWE-78     CRITICAL   PASS
cmdi_eval                             1    1  CWE-78     CRITICAL   PASS
cmdi_os_system                        1    1  CWE-78     CRITICAL   PASS
path_trav_join                        1    1  CWE-22     HIGH       PASS
path_trav_send_file                   1    1  CWE-22     HIGH       PASS
path_trav_open                        1    1  CWE-22     HIGH       PASS
ssti_template_string                  1    1  CWE-1336   CRITICAL   PASS
ssrf_requests_get                     1    1  CWE-918    CRITICAL   PASS
deser_pickle_loads                    1    1  CWE-502    CRITICAL   PASS
xss_reflected_markup                  1    1  CWE-79     HIGH       PASS
safe_parameterized  (FP check)        0    0  -          -          PASS
safe_shlex_quote    (FP check)        0    0  -          -          PASS
safe_render_template (FP check)       0    0  -          -          PASS
safe_hardcoded_url  (FP check)        0    0  -          -          PASS
safe_yaml_load      (FP check)        0    0  -          -          PASS
safe_escaped_xss    (FP check)        0    0  -          -          PASS
safe_cmdi_shlex     (FP check)        0    0  -          -          PASS
js_sqli_template    (JS)              1    1  CWE-89     CRITICAL   PASS
js_cmdi_exec        (JS)              1    1  CWE-78     CRITICAL   PASS
js_path_trav_sendfile (JS)            1    1  CWE-22     HIGH       PASS
js_xss_res_send     (JS)              1    1  CWE-79     HIGH       PASS
js_ssrf_fetch       (JS)              1    1  CWE-918    HIGH       PASS
js_deser_unserialize (JS)             1    1  CWE-502    CRITICAL   PASS
js_ssti_ejs         (JS)              1    1  CWE-1336   HIGH       PASS
js_safe_parameterized (JS FP check)   0    0  -          -          PASS
js_safe_execfile    (JS FP check)     0    0  -          -          PASS
js_safe_dompurify   (JS FP check)     0    0  -          -          PASS
ctx_escape_to_sql   (context-san)     1    1  CWE-89     LOW        PASS
so_stored_xss       (second-order)    1    1  CWE-79     HIGH       PASS
so_stored_sqli      (second-order)    1    1  CWE-89     HIGH       PASS
redirect_open                         1    1  CWE-601    MEDIUM     PASS
redirect_safe       (FP check)        0    0  -          -          PASS
log_injection_basic                   1    1  CWE-117    LOW        PASS
log_injection_safe  (FP check)        0    0  -          -          PASS
ldap_injection_basic                  1    1  CWE-90     HIGH       PASS
ldap_safe           (FP check)        0    0  -          -          PASS
xxe_basic                             1    1  CWE-611    HIGH       PASS
xxe_safe            (FP check)        0    0  -          -          PASS
race_toctou                           1    1  CWE-362    MEDIUM     PASS
auth_bypass                           1    1  CWE-287    HIGH       PASS
auth_safe           (FP check)        0    0  -          -          PASS
45/45 passed
```

### Cross-file taint tracking (3/3)

```
Test              CWE      Source file       Sink file    Result
golden_test       CWE-89   rate_limiter.py   logger.py    PASS  (3-file header→state→SQL)
session_poison    CWE-78   login.py          admin.py     PASS  (session["user"]→os.system)
return_value      CWE-78   utils.py          handler.py   PASS  (return value→subprocess)
```

### Real-world CVE validation

| CVE | Project | Vuln Class | CWE | VEXIS Detected |
|-----|---------|-----------|-----|----------------|
| CVE-2022-34265 | Django 3.2.x/4.0.x (`Trunc`/`Extract` injection) | SQL Injection | CWE-89 | CRITICAL |
| CVE-2023-30553 | Archery SQL audit platform v1.9.0 | Command Injection | CWE-78 | CRITICAL |
| CVE-2023-47890 | pyLoad download manager < 0.5.0b3.dev75 | Path Traversal | CWE-22 | HIGH |

---

## How it works

```
1. INGESTION
   Tree-sitter parses Python / JS / TS / JSX / TSX → AST → Program Dependency Graph (PDG)
   Framework detector identifies Flask / Django / FastAPI / Express
   Framework profile adds framework-specific sources, sinks, sanitizers
   CallGraphBuilder links cross-file function calls

2. TAINT ANALYSIS
   Worklist algorithm propagates taint from sources → sinks
   Context-sensitive sanitizer check: effective_for per vuln_class
   Tracks partial sanitizers, cross-file flows, JS callback patterns

3. AI REASONING
   Pass 1 (Sanitizer Eval): Can the sanitizer be bypassed?
   Pass 2 (Exploit Confirm): Is the path actually exploitable?
   Pass 3 (Chain Discovery): Do low-severity paths combine into critical attacks?
   LLMBudget: max calls per scan; taint-only fallback when exhausted

4. EXPLOIT CONSTRUCTION
   PoC generator creates working payloads
   Attack flow graph for visualization (chain edges as dashed purple)
   CVSS-style severity scoring
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full technical deep-dive.

---

## Real-world validation

Scanned `gothinkster/flask-realworld-example-app` (30 Python files, SQLAlchemy ORM):
- **0 false positives** — ORM-based apps produce no findings

Scanned `pallets/flask` tutorial (flaskr, 9 files, raw sqlite3 with parameterized queries):
- **2 false positives** — taint engine correctly traces `request.form → db.execute(?, params)` but LLM reasoning correctly marks them "NOT exploitable — parameterized query"
- Known limitation: parameterized-query recognition is on the roadmap

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Parser | Tree-sitter (Python, JS, TS, TSX grammars) |
| Taint Engine | NetworkX + custom worklist algorithm |
| LLM primary | Google Gemini (`gemini-flash-latest`) with `response_schema` |
| LLM fallback | Ollama (llama3) → Anthropic Claude |
| API | FastAPI + asyncio |
| Database | PostgreSQL 16 + SQLAlchemy async |
| Cache/queue/pubsub | Redis + Celery workers (async scanning) |
| Frontend | Next.js 14 + Tailwind CSS + D3.js |
| Real-time | WebSocket (FastAPI native) |
| Infrastructure | Docker Compose |

---

## Development

```bash
# Run unit tests (no LLM required)
pytest backend/tests/test_taint_engine.py -v

# Quick 4-sample smoke test
python -X utf8 backend/tests/run_e2e.py

# Run full 32-sample corpus (21 Python + 10 JS/TS + 1 context sanitizer; requires LLM API key)
python -X utf8 backend/tests/run_full_corpus.py

# Run cross-file taint scenarios
python -X utf8 backend/tests/run_cross_file.py

# Run real-world CVE validation
python -X utf8 backend/tests/run_real_world.py

# Run Semgrep comparison benchmark
python -X utf8 backend/tests/benchmark/semgrep_comparison.py
# Results written to backend/tests/benchmark/results.md
```

---

## Project structure

```
vexis/
├── backend/
│   ├── app/
│   │   ├── api/routes/       # scan, findings, stats, triage, reports
│   │   ├── api/ws/           # WebSocket real-time progress
│   │   ├── core/             # orchestrator (single-file + multi-file modes), git_ops
│   │   ├── ingestion/        # parser, PDG builder, call graph, trust boundaries
│   │   ├── taint/            # engine (worklist + cross-file), cross_file linker
│   │   ├── reasoning/        # LLM client (Gemini→Ollama→Anthropic), Pass 1/2/3, budget
│   │   ├── correlation/      # fuser, deduplication, confidence scoring
│   │   └── exploit/          # PoC generator, attack flow, CWE classifier
│   └── tests/
│       ├── run_e2e.py            # 4-sample quick smoke test
│       ├── run_cross_file.py     # 3-scenario cross-file taint test
│       ├── run_full_corpus.py    # 21-sample corpus test
│       ├── run_real_world.py     # CVE-based real-world validation
│       ├── vulnerable_samples/   # intentionally vulnerable Python samples
│       │   ├── sqli/
│       │   ├── cmdi/
│       │   ├── path_traversal/
│       │   └── cross_file/
│       └── real_world/           # CVE-attributed real-world snippets
└── frontend/
    └── src/
        ├── app/              # Next.js pages (landing, dashboard, scan, finding)
        └── components/       # AttackFlowGraph (D3), ScanProgress (WebSocket)
```

---

## Environment variables

```bash
# backend/.env
GOOGLE_API_KEY=your_gemini_key         # Primary LLM (recommended)
ANTHROPIC_API_KEY=your_claude_key      # Fallback LLM (optional)
DATABASE_URL=postgresql+asyncpg://vexis:vexis@postgres:5432/vexis
REDIS_URL=redis://redis:6379
OLLAMA_BASE_URL=http://host.docker.internal:11434
VEXIS_SCAN_TIMEOUT_SECONDS=600         # Per-scan timeout (default: 600)
VEXIS_MAX_LLM_CALLS_PER_SCAN=100       # LLM call budget per scan (default: 100)
```

---

## License

MIT
