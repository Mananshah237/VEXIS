# VEXIS — Project Status

Last updated: 2026-03-29

---

## Current state: Sprint 9 complete

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
