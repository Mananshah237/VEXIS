# VEXIS Real-World Repository Scan Results

> Sprint 3 benchmark — scanning public open-source Flask applications.
> All scans run against VEXIS API at `http://localhost:8000`.

---

## Repo 1: gothinkster/flask-realworld-example-app

| Attribute | Value |
|-----------|-------|
| Source | https://github.com/gothinkster/flask-realworld-example-app |
| Type | Full-stack Flask REST API (Conduit clone) |
| ORM | SQLAlchemy (all queries via ORM) |
| Python files | 30 |
| Taint paths | 0 |
| Findings | 0 |
| False positives | 0 |
| Semgrep findings | 0 |

### Analysis

VEXIS correctly produced **zero findings**. The application uses SQLAlchemy ORM exclusively — all database interactions are mediated through ORM methods (`db.session.query(...)`, model `.filter()` calls) which produce parameterized queries internally. The taint engine found no direct source→sink paths because no user input reaches a raw SQL execution function.

**Verdict: True Negative (correct)**

---

## Repo 2: pallets/flask — Tutorial App (flaskr)

| Attribute | Value |
|-----------|-------|
| Source | https://github.com/pallets/flask (examples/tutorial/) |
| Type | Flask tutorial blog app (flaskr) |
| Database | sqlite3 with parameterized queries (`?` placeholders) |
| Python files | 9 |
| Taint paths found | 8 |
| LLM calls used | 8 |
| Findings reported | 2 |
| True positives | 0 |
| False positives | 2 |

### Findings Detail

Both reported findings are **false positives**. The taint engine correctly traces user input from `request.form[...]` to `db.execute(query, params)`, but the queries use `?` parameterization — the user data is passed as a separate parameter tuple, never interpolated into the SQL string.

| # | File | Source | Sink | LLM Verdict |
|---|------|--------|------|-------------|
| 1 | auth.py | `request.form["username"]` line 53 | `db.execute("INSERT INTO user ... VALUES (?, ?)", ...)` line 65 | **NOT exploitable** — parameterized query |
| 2 | blog.py | `request.form["title"]` line 64 | `db.execute("INSERT INTO post ... VALUES (?, ?, ?)", ...)` line 75 | **NOT exploitable** — parameterized query |

### LLM Reasoning (excerpt)

> "The code uses parameterized queries (placeholders `?`) provided by the database driver. In the call `db.execute(query, parameters)`, the username variable is passed as a parameter in a tuple. This ensures that the database driver treats the input strictly as data and not as part of the SQL command."

### Known Limitation

The **taint engine cannot distinguish between parameterized queries and string-interpolated queries** at the structural level. When it sees `db.execute(sql_string, (user_input, ...))`, it traces the `user_input` → `db.execute` path as potentially dangerous, even though the parameterized form is safe.

The LLM reasoning pass correctly identifies both findings as non-exploitable, but the current fuser thresholds (`taint_conf=0.8, llm_conf=1.0`) classify them as `needs_manual_review` rather than `is_false_positive` because the LLM confidence (in its own answer) is 1.0 — it is very confident the pattern is safe, not that it's dangerous.

**Planned fix:** Recognize the `db.execute(query_literal, param_tuple)` pattern in the taint engine (parameterized-query sanitizer).

**Verdict: 2 False Positives — known limitation, LLM reasoning is correct**

---

## Semgrep Comparison on flaskr

| Tool | Findings | Correct |
|------|----------|---------|
| VEXIS | 2 (FP) | LLM reasoning says safe ✓ |
| Semgrep (auto) | 0 | Correct ✓ |

Semgrep's `python.lang.security.audit.formatted-sql-query` rule only fires on f-string / `%`-format / `.format()` SQL construction — parameterized `?` calls are excluded by rule design. VEXIS's taint engine is more aggressive (captures more paths) but relies on LLM pass to filter out safe parameterized calls.

---

## Summary

| Repo | Files | VEXIS Findings | True Positives | False Positives | Notes |
|------|-------|----------------|----------------|-----------------|-------|
| flask-realworld-example-app | 30 | 0 | 0 | 0 | SQLAlchemy ORM — clean |
| flaskr (tutorial) | 9 | 2 | 0 | 2 | Parameterized SQLite — FP on `db.execute(?, params)` |

### Key Takeaways

1. **VEXIS handles ORM-heavy apps correctly** — SQLAlchemy-based apps produce zero false positives.
2. **Parameterized raw SQL is a known FP source** — the taint engine flags the data flow correctly but can't see that `?` prevents injection. The LLM reasoning correctly identifies these as safe.
3. **LLM reasoning adds real value** — without the LLM pass, VEXIS would have reported 8 findings (all taint paths); the LLM eliminated 6 outright and correctly reasoned on the remaining 2.
4. **Next step:** Add a parameterized-query pattern recognizer to the taint engine to reduce these FPs before they reach the LLM.
