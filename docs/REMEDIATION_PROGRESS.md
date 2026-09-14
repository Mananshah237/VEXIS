# Review remediation progress

Reference: VEXIS technical and product review dated 14 September 2026.
This records implemented changes, not a declaration of launch readiness.

## Implemented

- **F01 — deployment configuration:** Settings accept documented `VEXIS_`
  names and legacy unprefixed names, with prefixed names taking precedence.
  Omitted deployment mode defaults to production. Explicit local modes retain
  development behavior. API startup and Celery worker startup validate secrets
  and auth enforcement. Invalid Fernet keys and short storage secrets fail
  startup. Compose passes the queue toggle to the API and shares scan limits
  with the worker. `.env.example` explicitly selects local development.
- **F03 — action retrieval failures:** HTTP errors, invalid JSON, malformed
  findings, unknown severity, duplicate IDs, and inconsistent pagination fail
  the action without publishing success counts. Complete empty responses still
  pass. Findings have deterministic ordering across tied scores.
- **F04 — immediate containment:** Incremental requests perform full-project
  analysis without consulting the previous unscoped baseline. Scan statistics
  expose `analysis_mode=full` and `incremental_requested`. Regression coverage
  checks that both changed entry points and unchanged dependencies reach the
  cross-file analysis stage.

## Filesystem hardening implemented; further assurance needed

- **F02:** Checkouts containing symbolic links, Windows junctions, or special
  files are rejected before analysis. Both private clone and public-cache copy
  paths validate their trees. Cache copies preserve links instead of
  dereferencing them and validate the copied tree again. The parser rejects
  links in path components; POSIX reads use descriptor-relative no-follow opens.
  Windows relies on exclusive ownership of temporary scan directories to avoid
  concurrent path replacement. This does not establish worker isolation.
- **F05/F06 partial:** GitHub tokens are rejected for other Git providers.
  Private clone failures/timeouts and unsafe cache copies clean up their scan
  directories. Successfully acquired Git checkouts are registered for normal
  scan cleanup. Cancelled Git subprocesses are killed and reaped. Credentials
  in clone URLs, browser sessions, and `/auth/me` remain to be fixed.

## Validation

The existing 33 Python tests and 61 action/security regressions passed locally.
Two subsequent orchestration regression cases also passed. Three real-symlink
cases were skipped because this Windows host lacks symlink creation privileges;
they are included in Linux CI and have not yet been verified there. No live
OAuth, remote clone, Docker deployment, or paid model calls were used.

## Next work

1. Remove GitHub credentials from browser-visible sessions, public identity
   responses, process arguments, and saved Git remotes.
2. Unify API/worker timeout and job-status handling, enforce resource limits,
   and test cancellation/cleanup end to end.
3. Fix sanitizer propagation and lexical variable scoping with adversarial
   safe/vulnerable pairs.
4. Repair multi-file ingestion paths and language identity.
5. Repair dependency locks and frontend dependency exposure; run reproducible
   installs and builds.
6. Complete stable finding identity and comparison semantics. Full-scan
   fallback alone does not fix temporary paths, partial scans, or historical
   scans incorrectly presented as resolved.
