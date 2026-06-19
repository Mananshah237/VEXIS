# Disaster Recovery — VEXIS

Scope: the VEXIS stack — FastAPI API, PostgreSQL, Redis/Celery, and MinIO object
storage (`docker-compose.yml`), plus the Railway-hosted deployment.

## Objectives

| Metric | Target | Rationale |
|--------|--------|-----------|
| **RTO** | ≤ 1 hour | Stateless API/worker rebuild from image; restore is dominated by DB + object-store restore. |
| **RPO** | ≤ 24 hours (DB), ≤ 24 hours (objects) | Nightly PostgreSQL dump + MinIO bucket sync. Scans are re-runnable, so the authoritative loss window is user/account data. |

## What is stateful

- **PostgreSQL** — users (incl. encrypted GitHub tokens / API keys), scans,
  findings, autofixes. **Authoritative state.**
- **MinIO** — uploaded code bundles, generated artifacts, reports. Large but
  partially regenerable (reports/artifacts re-derive from a re-scan; uploaded code
  bundles do not).
- **Redis** — Celery broker/results. Ephemeral; lost queue ⇒ scans re-run.

## Schema / migrations

- Alembic migrations live in `backend/alembic/versions/` (initial schema
  `0001_initial_schema`). Recovery applies migrations to head before restoring data:
  `alembic upgrade head`.
- A startup auto-migration list (`_SCHEMA_MIGRATIONS`) adds late columns on boot for
  existing DBs; Alembic is the source of truth for a clean rebuild.

## Backup

```bash
# PostgreSQL (nightly)
pg_dump "$DATABASE_URL" | gzip > backups/vexis-db-$(date +%F).sql.gz

# MinIO buckets (nightly)
mc mirror --overwrite local/vexis-code     backups/objects/$(date +%F)/code
mc mirror --overwrite local/vexis-artifacts backups/objects/$(date +%F)/artifacts
mc mirror --overwrite local/vexis-reports   backups/objects/$(date +%F)/reports
```

- Retain 14 daily + 8 weekly, off-host, encrypted at rest (the DB holds encrypted
  GitHub tokens — protect the app encryption key separately, see DATA_RETENTION.md).
- **Back up the field-encryption key** (`VEXIS_ENCRYPTION_KEY`) in a secrets
  manager. Losing it makes the encrypted GitHub-token/API-key columns unrecoverable.

## Restore

```bash
docker compose up -d db minio
alembic upgrade head
gunzip -c backups/vexis-db-YYYY-MM-DD.sql.gz | psql "$DATABASE_URL"
mc mirror backups/objects/YYYY-MM-DD/code local/vexis-code   # repeat per bucket
docker compose up -d                                          # api, worker, frontend
```

Verify: `GET /health`, authenticated `GET /scans`, open a finding, regenerate a fix.

## Failure runbook

1. **API/worker down, data intact** — redeploy image; check `/health`.
2. **DB lost** — recreate, `alembic upgrade head`, restore dump.
3. **MinIO lost** — restore buckets; missing reports/artifacts are regenerable by
   re-scanning; uploaded bundles are not (flag affected scans).
4. **Encryption key lost** — encrypted columns are unrecoverable; force users to
   re-link GitHub (the OAuth flow re-issues a token) and re-enter API keys.
5. **Secret rotation** — rotating `JWT_SECRET` invalidates sessions (re-auth).

## Gaps / TODO

- Backups are operator-driven; schedule them in the Railway/host environment.
- No PITR/replica — acceptable for current scale; add a managed-Postgres replica if
  VEXIS moves to higher availability tiers.
