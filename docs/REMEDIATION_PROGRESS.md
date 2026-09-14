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

## Detection reliability

- **F08 — receiver-agnostic SQL sinks:** SQL execution is matched by a regex
  (`<receiver>.execute(` / `.executemany(`) instead of a fixed set of receiver
  names. `conn`, `connection`, `db`, `session`, and arbitrary names such as
  `my_database` are now detected identically to `cursor`. Parameterized-query
  sanitizers still clear the safe cases.
- **F09 — context-sensitive sanitizers:** Propagation-time early termination no
  longer prunes on a class-agnostic constraint. A class-specific sanitizer
  (e.g. `html.escape` → xss only) can no longer erase an SQLi path; the sink
  applies sanitizers class-sensitively. `html.escape` still clears XSS.
- **F10 — scoped variable definitions:** PDG definitions are keyed by their
  enclosing function scope, so identically-named locals in unrelated functions
  are no longer wired into a single dataflow. Module-level globals still
  resolve. Intra-function flow is unchanged.
- **F12 — second-order table identity:** Second-order findings now require the
  read to pull from a table a tainted write populated, not mere line proximity.
  Constant queries (`SELECT 1`/`SELECT 2`) near a read no longer fire. Non-
  injectable constant-string SELECT sinks were removed. Findings are marked
  heuristic in their taint path.
- **F13 — discovery mode wiring:** `ScanConfig.discovery_mode` is a real field,
  so the flag survives the public request model. The pass reads the actual
  `ParsedFile.path` interface, validates findings against files/lines actually
  shown to the model with repository-relative paths, and reports a status
  (`completed` / `skipped_no_source` / `budget_exhausted` / `failed`) into scan
  stats instead of silently completing.
- **F14 — ingestion integrity:** Raw-code submissions preserve normalized
  relative paths within the scan root, reject traversal, absolutes, duplicates,
  and unsupported extensions (no silent `.py` rename), and derive the language
  of a single snippet from the declared language. TSX now routes to the TSX
  grammar rather than the plain TypeScript grammar.
- **F18 — exploit templates:** The generic default template's `KeyError: 'r'`
  is fixed, payload literals are escaped safely, generated scripts are
  syntax-checked, and the orchestrator counts only scripts actually produced.
  Exploit-script refinement now draws on the shared scan LLM budget.

Regression coverage for F08–F14 and F18 lives in
`tests/test_detection_quality.py` (22 cases) and runs in CI.

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
3. Repair dependency locks and frontend dependency exposure; run reproducible
   installs and builds.
4. Complete stable finding identity and comparison semantics. Full-scan
   fallback alone does not fix temporary paths, partial scans, or historical
   scans incorrectly presented as resolved.
5. Strengthen cross-file/interprocedural resolution (F11) and add strict typed
   LLM output validation with provenance (F15/F16). Bind fixes to immutable
   commit/blob identities and validate before proposing PRs (F17).
6. Replace receiver/sink string heuristics with resolved imported-API and
   receiver-type provenance (the deeper half of F08), and add reaching-def
   ordering/kills to the PDG (the deeper half of F10).
