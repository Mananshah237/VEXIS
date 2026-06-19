# Data Retention & Deletion — VEXIS

VEXIS scans source code (often from private GitHub repos) and stores findings plus
the credentials needed to read those repos. This document records retention,
deletion, and the encryption of sensitive columns.

## What we store

| Data | Location | Sensitivity |
|------|----------|-------------|
| User (GitHub identity, email) | `users` | PII |
| GitHub access token (repo scope) | `users.github_token` | **Secret — encrypted at rest** |
| Provider API keys | `users` | **Secret — encrypted at rest** |
| Scans (repo URL, status, owner) | `scans` | Medium |
| Findings (vuln locations, taint paths, autofixes) | `findings` | Medium — reveals a repo's weaknesses |
| Uploaded code bundles / artifacts / reports | MinIO | Medium–High — third-party source code |

Secrets in the `users` table are encrypted with application-layer encryption
(`app/core/crypto.py`, Fernet) using `VEXIS_ENCRYPTION_KEY`. A DB leak alone does
not expose GitHub tokens or API keys. Clones use a fresh authenticated clone so the
token never lands in a cache key or log.

## Tenant isolation

Every scan/finding/object is owned by a user; reads and writes are scoped to the
authenticated owner. Anonymous, unowned scans are no longer world-readable
(2026-06-18 hardening) — authentication is required to create and read scans.

## Retention

| Data | Default retention | Notes |
|------|-------------------|-------|
| Scans + findings | 180 days | Re-runnable; configurable. |
| Object-store artifacts/reports | 90 days | Regenerable from a re-scan. |
| Uploaded code bundles | Deleted after scan completes (+ 7-day grace) | Minimize third-party code at rest. |
| GitHub token | Until revoked / account deleted | Encrypted; re-issued by re-linking GitHub. |

## Deletion (data-subject / GDPR right-to-erasure)

Implemented: **`DELETE /auth/me`** deletes the caller's account and **all** owned
data — findings, scans, the user row, and best-effort purge of every owned object
across the code/artifact/report buckets (`app/api/routes/auth.py`).

```
DELETE /auth/me      # authenticated; cascades findings -> scans -> user + MinIO objects
```

## Compliance posture (honest)

- **GDPR**: lawful basis is the user scanning their own repositories. Supports
  access (export scans/findings) and erasure (`DELETE /auth/me`). GitHub tokens are
  encrypted and revocable.
- **HIPAA**: out of scope — VEXIS processes source code, not PHI.

## TODO

- Schedule automatic enforcement of the retention windows (currently policy +
  on-demand erasure).
- Add an authenticated data-export endpoint to round out the GDPR access right.
