# VEXIS — Security, Testing & Resilience Audit

**Audit date:** 2026-06-18
**Scope:** `C:\Users\mgroc\Downloads\projects\VEXIS` (read-only audit)
**Tech stack:**
- **Backend:** Python 3.12, FastAPI 0.115+, SQLAlchemy 2.0 (async, asyncpg), PostgreSQL 16, Redis 7, Celery 5.4, MinIO (S3-compatible object storage), python-jose (JWT), structlog. Static-analysis engine using tree-sitter + Semgrep + LLM reasoning (Gemini → Ollama → Anthropic fallback chain).
- **Frontend:** Next.js (App Router), NextAuth (GitHub OAuth provider), TypeScript.
- **CLI** + **GitHub Action** wrappers; **WeasyPrint** PDF reports.
- **Infra/deploy:** Docker Compose (api, celery_worker, frontend, postgres, redis, minio), Railway (`railway.toml`), GitHub Actions CI.
- **Migrations:** Alembic is a dependency and `railway.toml` runs `alembic upgrade head`, but **no `alembic/versions/` migration files exist** — schema is created at runtime via `Base.metadata.create_all` + hardcoded `ALTER TABLE ... IF NOT EXISTS` in `main.py`.

---

## Executive Summary

- **Authorization model is "ownership-or-anonymous," and anonymous scans are world-readable.** IDOR checks are applied consistently (`scan.user_id is not None` gate in every route), but any scan created without authentication has `user_id = NULL` and is then readable/listable by *any* unauthenticated caller (`backend/app/api/routes/scan.py:88`, `stats.py:26`). Authentication is entirely **optional** end-to-end (`backend/app/api/deps.py:1-5`), and the frontend auth middleware is **disabled** (`frontend/src/middleware.ts` matcher `[]`).
- **A live Google/Gemini API key sits in `VEXIS/.env` in plaintext.** The file is correctly git-ignored and **not tracked** (verified via `git ls-files`), so it is not in history — but it is a real credential at rest on disk and shipped as the repo's working default (`.env:7`). Treat it as compromised and rotate.
- **JWT secret defaults to empty string and tokens are still mintable with it.** `jwt_secret: str = ""` (`backend/app/config.py:91`); python-jose will HMAC-sign with an empty key, so if `JWT_SECRET` is unset in production every party can forge tokens. There is no startup assertion that the secret is non-empty/strong. Dev defaults (`vexis-dev-jwt-secret-change-in-prod`, `NEXTAUTH_SECRET=vexis-dev-secret-change-in-prod`) are baked into `.env` and `docker-compose.yml`.
- **SSRF, command injection, and SQLi defenses are genuinely good.** Repo URLs go through an HTTPS host allowlist + suspicious-char regex (`backend/app/core/git_ops.py:54`), git runs via `create_subprocess_exec` (no shell), server-side path scanning is blocked, raw-code is size-capped, and all DB access is ORM-parameterized (no raw SQL string interpolation found).
- **Testing is shallow for an application of this size.** The HTTP API has effectively one real test (`/health`); `test_api.py` is 8 lines. The substantive tests cover the *taint engine* and vulnerable-sample corpus, not auth/IDOR/rate-limiting. CI runs only 2 pytest files, has **no coverage gate**, no security scanning (no `pip-audit`/`saf/CodeQL`), and no e2e/load/chaos testing.
- **Resilience basics are present but partial.** LLM provider fallback chain + Redis prompt cache + per-URL clone locks + graceful MinIO/Redis degradation are real strengths. But there is **no retry/backoff with idempotency on scan creation**, no circuit breaker, no documented RTO/RPO, no backup/DR plan, and **no data-deletion/GDPR endpoints anywhere** (no `@router.delete` exists).

**Overall security maturity: Low-to-Medium.** **Testing maturity: Low.** **Resilience maturity: Medium.**

---

## Scorecard

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1 | Input sanitization / injection (SQLi, cmdi, XSS, path, SSRF, deser, prompt) | 🟡 Partial | Strong SSRF/cmdi/SQLi defenses; LLM prompt-injection surface unmitigated; presigned URLs broadly readable |
| 2 | AuthN/AuthZ, roles, permissions | 🟡 Partial | Auth fully optional; ownership-based AuthZ only; no roles; anonymous scans world-readable |
| 3 | Session management & token expiry | 🟡 Partial | 7-day JWT, no refresh/revocation/rotation; empty-secret default; no token blacklist |
| 4 | Secrets management | 🟡 Partial | `.env` git-ignored & untracked (good), but real Gemini key on disk; weak baked-in dev secrets; empty JWT default |
| 5 | HTTPS / TLS / cert rotation | ❌ Missing | No TLS in compose; MinIO `secure=False` hardcoded; no cert/rotation handling in app |
| 6 | Rate limiting / abuse prevention | 🟡 Partial | Redis daily cap for authed users only (3/day); anonymous users unlimited; fail-open on Redis error |
| 7 | Dependency scanning / pinned deps | 🟡 Partial | `uv.lock` pins transitives; direct deps use floating `>=`; no `pip-audit`/Dependabot/SCA in CI |
| 8 | Multi-tenancy / data isolation | 🟡 Partial | Per-route ownership checks consistent; NULL-owner (anonymous) rows are a shared global tenant |
| 9 | PII handling / retention / deletion | ❌ Missing | Stores email + GitHub OAuth token in plaintext; no retention policy; no delete endpoints |
| 10 | Regulatory compliance (GDPR/HIPAA) | ❌ Missing | No DPA, consent, erasure, or data-subject mechanisms; not addressed in docs |
| 11 | Audit trails / tamper-evident logging | ❌ Missing | structlog app logs only; no security/audit log, no tamper-evidence, no log of auth events |
| 12 | Unit/integration/e2e tests | 🟡 Partial | Good taint-engine + corpus tests; API tests near-empty; e2e scripts exist but not in CI |
| 13 | Regression tests | 🟡 Partial | Real-world CVE samples & corpus act as regression for the engine; none for API/auth |
| 14 | Load / stress testing | ❌ Missing | No load/stress tooling or evidence |
| 15 | Chaos / resilience testing | ❌ Missing | None |
| 16 | Coverage thresholds in CI | ❌ Missing | `pytest-cov` installed but no `--cov-fail-under`; CI runs 2 files only |
| 17 | Code review process / linters / pre-commit | 🟡 Partial | ruff + mypy strict + CI lint job; no pre-commit hooks, no PR template, no CODEOWNERS |
| 18 | Error handling / graceful degradation | ✅ Present | Broad try/except around MinIO/Redis/LLM; storage failures never break a scan |
| 19 | Retry w/ backoff & idempotency | 🟡 Partial | LLM fallback chain + clone cache; no exponential backoff; scan creation not idempotent |
| 20 | Circuit breakers / fallback | 🟡 Partial | Provider fallback chain (Gemini→Ollama→Anthropic) acts as fallback; no real circuit breaker |
| 21 | Concurrency / race prevention | 🟡 Partial | Per-URL async clone locks; DB commits per request; rate-limit `incr` atomic; no row locks on scan state |
| 22 | Caching & invalidation | ✅ Present | Redis LLM prompt cache (1h TTL, hash key) + clone disk cache (TTL + fetch refresh) |
| 23 | RTO / RPO | ❌ Missing | Not defined anywhere |
| 24 | Disaster recovery (backups, migration rollback) | ❌ Missing | No backup config; no Alembic version files → no real migration history/rollback |
| 25 | Accessibility (frontend a11y) | ➖ N/A / unassessed | No a11y tooling (axe/eslint-jsx-a11y) or evidence found; not formally in scope of code reviewed |
| 26 | Architecture diagrams / ADRs | ✅ Present | `ARCHITECTURE.md` (22 KB) + `decisions.md` (22 KB ADR log) are thorough and high quality |

---

## Findings

### A. Input Sanitization & Security

#### 1. Injection prevention — 🟡 Partial
**Strengths (real and well done):**
- **SSRF / repo URL:** `backend/app/core/git_ops.py:54-61` enforces an HTTPS host allowlist (`github.com`, `gitlab.com`, `bitbucket.org`) and rejects URLs containing `[;&|`$<>]` or `..`. The scan router re-validates before DB insert (`scan.py:33-38`).
- **Command injection:** Git invoked via `asyncio.create_subprocess_exec("git", *args, ...)` (`git_ops.py:77-84`) — argument vector, no shell. No `os.system`/`shell=True` found in app code.
- **SQLi:** All queries use SQLAlchemy `select(...).where(Model.col == val)` with bound parameters. Grep for f-string/`.format` SQL found **zero** matches in `backend/app`.
- **Server-side file read / path traversal:** `scan.py:23-30` blocks `directory`/`file_upload` source types; only `github_url` and `raw_code` are accepted. Raw code capped at 10 MB (`scan.py:41-42`).

**Gaps:**
- **Prompt injection (LLM-backed):** Scanned source code and taint summaries are concatenated into LLM prompts (`backend/app/reasoning/llm_client.py:106-114`, autofix uses `finding.sink_code`/`llm_reasoning`) with no input fencing or output validation beyond required-field presence (`_validate_schema`, `llm_client.py:89-92`). Malicious repo content could steer the model (e.g., suppress findings or poison autofix output that is then committed via PR). **Recommendation:** sandbox/escape untrusted code in prompts, treat model output (especially autofix patches and exploit scripts) as untrusted, and require human review before PR (the PR body says "please review" but the patch is still auto-generated from attacker-controlled file content).
- **Presigned URL exposure:** `backend/app/core/storage.py:108` issues 1-hour presigned GET URLs and `scan.py:189-210` lists artifact URLs. Access is gated by scan ownership, but for anonymous (`user_id NULL`) scans anyone can mint download URLs to the snapshotted source code.

**Recommendation:** add a prompt-injection mitigation layer; consider not snapshotting/serving source for anonymous scans.

#### 2. AuthN / AuthZ / roles — 🟡 Partial
- Authentication is **optional by design**: `backend/app/api/deps.py:1-5,54` returns `None` for missing/invalid credentials and every route accepts `current_user: dict | None`. Invalid API keys and invalid JWTs are silently downgraded to anonymous (`deps.py:35,45`) rather than rejected.
- **No role/permission model** — authorization is purely resource-ownership (`str(scan.user_id) != str(current_user["id"])`). There is no admin/role concept.
- IDOR protection is applied **consistently** across `scan.py`, `findings.py`, `autofix.py`, `reports.py`, `exploit.py`, `triage.py`, `differential.py` (each loads the parent `Scan` and checks `user_id`). Returns 404 (not 403) to avoid enumeration — good.
- **The structural weakness:** the ownership check is only enforced `if scan.user_id is not None`. Anonymous scans (`user_id NULL`) bypass it entirely (`scan.py:88-90`, `findings.py:30-32`). Because auth is optional, the default path creates exactly these world-readable rows.

**Recommendation:** make auth mandatory for non-public endpoints, assign every scan an owner (even a session/guest id), and remove the `is not None` escape hatch.

#### 3. Session management & token expiry — 🟡 Partial
- JWT HS256, 7-day expiry (`config.py:93`, `auth.py:11-19`). No refresh tokens, no revocation list, no rotation, no `jti`/blacklist. Logout cannot invalidate an issued token.
- API keys (`secrets.token_hex(32)`, `auth.py:27-29`) are stored **in plaintext** in `users.api_key` (`models/user.py:19`) and never expire.

**Recommendation:** shorten JWT lifetime + add refresh/rotation; hash API keys at rest; support revocation.

#### 4. Secrets management — 🟡 Partial
- **Good:** `.gitignore` excludes `.env`, `backend/.env`, `frontend/.env.local`, `.claude/`, and `CLAUDE.md` (`.gitignore:1-37`). `git ls-files` confirms **only `.env.example` is tracked** — no real secret is in git or history.
- **Bad:** `VEXIS/.env:7` contains a **real Gemini API key** (`AQ.Ab8RN6L-...`) in plaintext on disk and is the shipped working default. `.env:15-16` and `docker-compose.yml:16,59,94` bake weak dev secrets (`vexis-dev-jwt-secret-change-in-prod`, `vexis-local-dev-secret`).
- **Empty defaults that are dangerous in prod:** `jwt_secret=""` (`config.py:91`), `minio_secret_key=""` (`config.py:84`), `storage.py:32` falls back to literal `"vexis_dev_password"`. None are asserted at startup.

**Recommendation:** rotate the leaked Gemini key now; add a startup check that `JWT_SECRET`/`MINIO_SECRET_KEY` are set and not the dev defaults when not in dev mode; move secrets to a manager (Railway/SSM/Vault).

#### 5. HTTPS / TLS / cert rotation — ❌ Missing
- No TLS termination in `docker-compose.yml`; api/frontend served over plain HTTP. MinIO client hardcoded `secure=False` (`storage.py:33`). Railway provides TLS at its edge, but nothing in-app enforces HTTPS (no HSTS, no secure-cookie enforcement visible in backend). No cert rotation strategy.

**Recommendation:** terminate TLS at a reverse proxy, set HSTS, ensure cookies are `Secure`+`HttpOnly`+`SameSite`, and enable MinIO TLS in prod.

#### 6. Rate limiting / abuse prevention — 🟡 Partial
- `backend/app/core/rate_limiter.py`: Redis `INCR` with 24h TTL, **3 scans/day for authenticated users only**. Anonymous users return `(True, LIMIT)` unconditionally (`rate_limiter.py:18-19`) — i.e., **no limit at all on the default unauthenticated path**, which is also the cheapest to abuse.
- **Fail-open:** any Redis error returns `allowed=True` (`rate_limiter.py:35-37`).
- No global request rate limiting, no IP-based throttling, no WAF, no limit on the expensive LLM passes per anonymous caller.

**Recommendation:** rate-limit anonymous callers by IP; fail closed (or degrade to a low cap) on Redis errors; add a global limiter (e.g., slowapi).

#### 7. Dependency scanning & pinning — 🟡 Partial
- `backend/pyproject.toml` direct deps use floating lower bounds (`fastapi>=0.115.0`, etc.). `backend/uv.lock` exists and pins the resolved transitive tree (good for reproducibility).
- **No SCA in CI** — `.github/workflows/ci.yml` runs ruff + 2 pytest files + frontend build only. No `pip-audit`, `uv pip audit`, Dependabot, Snyk, or CodeQL. No frontend `npm audit`.

**Recommendation:** add `pip-audit`/`npm audit` and Dependabot; pin direct deps to compatible ranges.

#### 8. Multi-tenancy / data isolation — 🟡 Partial
- Row-level scoping via `user_id` is implemented and **consistent**; aggregate endpoints are correctly scoped (`stats.py:20-29`, `scans/recent` `stats.py:65-70`).
- The single isolation hole is the **shared anonymous tenant** (`user_id NULL`): all unauthenticated callers see the same pooled anonymous scans/findings/stats. There is no org/team concept.

**Recommendation:** eliminate the global anonymous bucket; scope guests to a session identifier.

#### 9. PII handling / retention / deletion — ❌ Missing
- Stores user email, GitHub login, avatar, and **GitHub OAuth token** (`models/user.py:17-21`) — the OAuth token is requested with `repo` scope (`frontend/src/lib/auth.ts:14`) and stored in **plaintext** (`users.github_token TEXT`). Compromise of the DB exposes write access to users' repositories.
- **No data-deletion or export endpoints** — grep for `@router.delete` returns nothing across all routes. No retention/TTL on scans, findings, code snapshots, or tokens.

**Recommendation:** encrypt `github_token` at rest (or store only short-lived scoped tokens), add account/scan deletion, and define retention TTLs for snapshots/artifacts.

#### 10. Regulatory compliance (GDPR / HIPAA) — ❌ Missing
- No consent flow, no right-to-erasure, no data-export, no DPA/privacy documentation. PII (email, OAuth token) is processed without any compliance scaffolding. HIPAA N/A to the use case, but GDPR obligations (EU users) are unmet.

**Recommendation:** add a privacy policy, erasure/export endpoints, and a data-processing inventory.

#### 11. Audit trails / tamper-evident logging — ❌ Missing
- Only operational structlog logging (e.g., `git.clone.private_done`, `minio.*`). No dedicated security audit log for authentication, API-key generation/rotation, PR creation, or data access. No tamper-evidence (append-only/signed logs). Auth failures are silently swallowed (`deps.py`) and never logged.

**Recommendation:** log security-relevant events (login, key issuance, PR open, ownership-denied 404s) to an append-only/immutable sink.

### B. Testing Strategies

#### 12. Unit / integration / e2e — 🟡 Partial
- **Inventory:** `test_taint_engine.py` (58 lines, ~2 asserts), `test_vulnerable_samples.py` (90 lines, ~10 asserts), `test_java_samples.py`, `test_polyglot_samples.py`, plus runner scripts (`run_e2e.py`, `run_real_world.py`, `run_full_corpus.py`, `run_cross_file.py`) and real-world CVE reproductions under `tests/real_world/`. **`test_api.py` is 8 lines and only checks `/health`.**
- **Run command:** `cd backend && uv run pytest` (CI runs only `tests/test_taint_engine.py` and `tests/test_api.py`).
- **Coverage:** `pytest-cov` is installed but never invoked with a threshold; no measured coverage figure.
- **Gap:** no integration tests for auth, IDOR, rate limiting, ownership 404s, or the autofix/PR pipeline — i.e., the security-critical paths are untested.

**Recommendation:** add API/auth integration tests (esp. IDOR and anonymous-access boundaries) and wire the e2e runners into CI.

#### 13. Regression tests — 🟡 Partial
- The real-world CVE samples (`cve_2022_34265_sqli.py`, `cve_2023_30553_cmdi.py`, `cve_2023_47890_path_traversal.py`) and the corpus runners serve as regression coverage **for the detection engine**. No regression tests guard the web/API layer.

#### 14. Load / stress testing — ❌ Missing
No locust/k6/artillery config or benchmarks for the API (the `benchmark/` dir compares detection vs Semgrep, not load).

#### 15. Chaos / resilience testing — ❌ Missing
None.

#### 16. Coverage thresholds in CI — ❌ Missing
`ci.yml` has no `--cov` / `--cov-fail-under`. No gate.

#### 17. Code review / linters / pre-commit — 🟡 Partial
- CI lint job: `ruff check` + `ruff format --check` + `mypy strict` configured (`pyproject.toml:56-66`). Good baseline.
- **Missing:** no `.pre-commit-config.yaml`, no `PULL_REQUEST_TEMPLATE`, no `CODEOWNERS`, no branch-protection evidence. mypy strict is configured but **not run in CI** (only ruff is).

**Recommendation:** add pre-commit hooks, run mypy in CI, add a PR template + CODEOWNERS.

### C. Resilience & Availability

#### 18. Error handling / graceful degradation — ✅ Present
- MinIO operations all wrapped in try/except and return falsy on failure so a scan never breaks (`storage.py` throughout). Redis cache/rate-limit failures degrade gracefully. LLM cache get/set swallow errors (`llm_client.py:68-87`). `main.py:37-41` tolerates failing schema-migration statements.
- *Caveat:* graceful degradation is sometimes **fail-open** (rate limiter, auth), which trades security for availability.

#### 19. Retry w/ backoff & idempotency — 🟡 Partial
- LLM has a one-shot "missing fields" retry and a provider fallback (`llm_client.py:131-153`); clone cache retries via fetch. **No exponential backoff** anywhere. **Scan creation is not idempotent** — no idempotency key; a retried POST creates duplicate scans (`scan.py:15-74`).

**Recommendation:** add backoff (e.g., tenacity) to external calls and an idempotency key on `POST /scan`.

#### 20. Circuit breakers / fallback — 🟡 Partial
- The Gemini→Ollama→Anthropic chain (`llm_client.py:2,106-153`) is a genuine fallback. No circuit breaker (no failure-rate tripping / cooldown) for the DB, Redis, MinIO, or GitHub API.

#### 21. Concurrency / race prevention — 🟡 Partial
- Per-URL async `asyncio.Lock` prevents double-clone (`git_ops.py:49-74,116`). Rate-limit `INCR` is atomic. Each request commits in its own session (`database.py`).
- **Gaps:** scan status transitions in the orchestrator/background task are not guarded by row locks (`SELECT ... FOR UPDATE`), and `Base.metadata.create_all` + ad-hoc `ALTER TABLE` at startup (`main.py:22-41`) can race across multiple replicas booting simultaneously.

**Recommendation:** use row-level locks for scan state mutations; move schema changes to Alembic run once, not per-process.

#### 22. Caching & invalidation — ✅ Present
- Redis LLM prompt cache keyed by SHA-256 of system+user prompt, 1h TTL (`llm_client.py:65-87`). Git clone disk cache with TTL + `git fetch` refresh (`git_ops.py:44-47,116-130`). Invalidation is TTL-based and sound for the use case.

#### 23. RTO / RPO — ❌ Missing
Not defined in any doc (grep of all `.md` found no RTO/RPO).

#### 24. Disaster recovery — ❌ Missing
- No DB backup configuration (compose uses a local volume only). **Alembic is configured to run on deploy (`railway.toml:6`) but `alembic/versions/` is empty**, so `upgrade head` is a no-op and there is no migration history to roll back. Schema lives in `create_all` + hardcoded ALTERs — no rollback path.

**Recommendation:** generate real Alembic migrations, enable managed Postgres backups (PITR), and document a restore runbook.

### D. Additional

#### 25. Accessibility (frontend a11y) — ➖ N/A / unassessed
No a11y tooling (`eslint-plugin-jsx-a11y`, axe) or audit evidence was found; frontend component-level a11y was outside the security-focused file review. No automated a11y gate exists.

#### 26. Architecture diagrams / ADRs — ✅ Present
- `ARCHITECTURE.md` (22 KB) and `decisions.md` (22 KB ADR-style log), plus `documentation.md` (29 KB), `DEPLOY.md`, and `LAUNCH_CHECKLIST.md`. Coverage and quality are high for design rationale and the analysis pipeline. **Gap:** docs do not cover security operations, threat model, RTO/RPO, backup/DR, or data-retention — the operational-security dimensions scored ❌ above.

---

## Top Priority Fixes (ordered)

1. **Rotate the exposed Gemini API key** in `VEXIS/.env:7` immediately, and stop shipping a real key as the repo default. Confirm it never reached a public remote (history is clean locally, but the working file is live).
2. **Fail closed on auth secrets.** Add a startup assertion that `JWT_SECRET` and `MINIO_SECRET_KEY` are set, non-empty, and not the baked-in dev values when running outside dev (`config.py:84,91`). An empty JWT secret currently lets anyone forge tokens.
3. **Close the anonymous-data hole.** Remove the `if scan.user_id is not None` escape hatch (`scan.py:88`, `findings.py:30`, etc.) — require authentication for scan/finding/report access, or scope guests to a per-session owner so anonymous data is not globally shared.
4. **Make auth real, not optional, for protected endpoints** (`backend/app/api/deps.py`): reject invalid/missing credentials with 401 on non-public routes instead of silently downgrading to anonymous; **re-enable the frontend middleware matcher** (`frontend/src/middleware.ts`).
5. **Rate-limit anonymous/unauthenticated callers** (by IP) and **fail closed** on Redis errors (`rate_limiter.py:18-19,35-37`); add a global limiter to protect the expensive LLM passes.
6. **Encrypt secrets at rest:** hash `users.api_key` and encrypt (or stop storing) `users.github_token` — a DB leak currently yields `repo`-scoped write access to users' GitHub accounts (`models/user.py:19,21`).
7. **Add security testing to CI:** `pip-audit`/`npm audit` + Dependabot, run `mypy` (already configured) and the e2e runners, and add API/auth/IDOR integration tests (the security paths are essentially untested today).
8. **Introduce a coverage gate** (`pytest --cov --cov-fail-under=N`) so the near-empty `test_api.py` cannot pass for the whole API surface.
9. **Generate real Alembic migrations** and stop relying on `create_all` + runtime `ALTER TABLE` (`main.py:22-41`); this also gives a rollback path. Enable managed Postgres backups and document RTO/RPO + a restore runbook.
10. **Mitigate LLM prompt injection / untrusted autofix output:** fence untrusted source in prompts, validate model output, and require explicit human approval before `POST /finding/{id}/pr` commits AI-generated patches derived from attacker-controlled repo content (`autofix.py:102-172`).
11. **Add audit logging** for auth events, API-key issuance, ownership-denied access, and PR creation to an append-only sink; log (don't silently swallow) auth failures in `deps.py`.
12. **Enforce TLS/secure cookies** end-to-end (HSTS, `Secure`/`HttpOnly`/`SameSite`), enable MinIO TLS in prod (`storage.py:33`), and add a GDPR-minimum account/scan **deletion** endpoint plus retention TTLs for snapshots and tokens.
