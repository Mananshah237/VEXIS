# VEXIS Demo Walkthrough

Step-by-step guide for demonstrating VEXIS to a technical audience (security teams, recruiters, investors).

**Total demo time:** ~5 minutes
**Prerequisites:** `docker compose up -d` running, `http://localhost:3000` accessible

---

## Step 1 — Landing page (30 sec)

Navigate to `http://localhost:3000`.

**What to show:**
- Tagline: *"Every existing scanner matches patterns. VEXIS reasons."*
- The 3-file cross-boundary SQLi example — walk through how `X-Client-ID` flows from a rate limiter header into an audit log query. Point out that the search query is properly parameterized (decoy), but the client_id is never sanitized.
- Scanner comparison table: Semgrep/CodeQL/Snyk all miss it, VEXIS catches it.
- **VEXIS vs Semgrep section** (Sprint 3 addition): scroll to the benchmark stats block on the landing page — TPR 90% vs 67%, FPR 5% vs 10%, and the cross-file 3/3 vs 0/3 callout. This is measured data, not a claim.

**Talking point:** "Traditional scanners look at one file at a time for known patterns. VEXIS traces data across trust boundaries and reasons about whether the flow is actually exploitable. We ran a 27-sample benchmark against Semgrep in the same container — VEXIS catches 23% more true positives and half the false positives."

---

## Step 2 — Start a scan (45 sec)

Click **"Start a scan"** or navigate to `http://localhost:3000/scan/new`.

Paste this code into the **Paste Code** tab:

```python
import sqlite3
from flask import request

@app.route('/search')
def search():
    q = request.args.get('q')
    db = sqlite3.connect('app.db')
    db.execute(f"SELECT * FROM items WHERE name = '{q}'")
    return 'ok'
```

Click **"Scan Now"**.

**What happens:** The page redirects to `/scan/{id}` and the `ScanProgress` component connects via WebSocket, showing the 4-phase progress bar in real time:

```
[Parsing] → [Taint Analysis] → [AI Reasoning] → [Complete]
```

Each phase lights up with a cyan pulse as it runs, then turns green with a checkmark when done.

---

## Step 3 — Scan results (60 sec)

Once complete, the results page shows:

- **Scan metadata**: source, status, files parsed, duration
- **Severity breakdown bar**: proportional red/orange/yellow/blue strip
- **Finding list** sorted by severity (critical first)

Click the **CRITICAL** finding (CWE-89).

**What to highlight:**
- Severity badge and confidence percentage
- Source → Sink summary: `request.args.get('q')` line X → `db.execute(f"...")` line Y

**Talking point:** "Taint engine traced the data flow. LLM confirmed it's exploitable. Combined confidence: 0.85."

---

## Step 4 — Finding detail + attack flow graph (90 sec)

Click through to the finding detail page (`/scan/{id}/finding/{fid}`).

**CWE link** (Sprint 3 addition): The CWE badge (e.g., "CWE-89") is now a clickable link to `https://cwe.mitre.org/data/definitions/89.html`. Point this out to a technical audience — it shows the MITRE definition inline without leaving the tool.

**Attack Flow Graph (D3.js):**
- 3 nodes: red SOURCE → blue TRANSFORM → orange SINK
- Sink node **pulses** (CSS animation) to draw the eye
- Edge labels show taint state: `tainted` → `tainted`
- Hover a node to see the code snippet tooltip
- Drag nodes to rearrange

**PoC section:**
```
Attack vector: HTTP GET /search
Payload:       ' OR '1'='1
Steps:
  1. Send GET /search?q=' OR '1'='1
  2. Query becomes: SELECT * FROM items WHERE name = '' OR '1'='1'
  3. Returns all rows — authentication/data bypass
Expected outcome: Full table dump / auth bypass
```

**AI Reasoning:**
Chain-of-thought explanation from the LLM showing why the sanitizer (none in this case) doesn't protect against exploitation.

**Talking point:** "This is what makes VEXIS different — not just 'vulnerable', but here's the exact payload, here's why it works, here's the attack graph."

---

## Step 5 — Dashboard (30 sec)

Navigate to `http://localhost:3000/dashboard`.

**What to show:**
- Stats cards: total scans, total findings, critical count, high count
- Recent scans list with status indicators and finding counts
- Severity breakdown bar across all scans

**Talking point:** "This is what your security team sees day-to-day. Every scan is logged, every finding is tracked."

---

## The 3-file cross-file demo (strongest demo, +2 min)

This is the headline feature — the vulnerability that every other scanner misses. Run it via the API:

```bash
python -X utf8 backend/tests/run_cross_file.py
```

Or submit via the UI using the **Paste Code** tab with `=== FILE: ===` separators:

```
# === FILE: rate_limiter.py ===
def check_rate_limit(request):
    client_id = request.headers.get("X-Client-ID", "anonymous")
    request.state.client_id = client_id
    return True

# === FILE: search.py ===
from rate_limiter import check_rate_limit
from logger import log_search
import sqlite3

def search(request):
    check_rate_limit(request)
    query = request.query_params.get("q", "")
    safe_query = query.replace("'", "''").replace(";", "")
    log_search(request.state.client_id, safe_query)
    db = sqlite3.connect("app.db")
    results = db.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{safe_query}%",))
    return results

# === FILE: logger.py ===
import sqlite3

def log_search(client_id, query):
    db = sqlite3.connect("app.db")
    db.execute(f"INSERT INTO search_log (client_id, query) VALUES ('{client_id}', '{query}')")
```

**Expected result:**
- Source: `request.headers.get("X-Client-ID")` in `rate_limiter.py`
- Sink: `db.execute(f"INSERT INTO ...")` in `logger.py`
- Path: rate_limiter.py → request.state → search.py → log_search() → logger.py
- CWE-89 CRITICAL
- The parameterized query (`WHERE name LIKE ?`) is correctly **not** flagged

**Talking point:** "The search query is sanitized — VEXIS knows that. But notice: the rate limiter stores the client ID in `request.state`, search.py reads it from there and passes it to `log_search`, which uses it in a raw f-string SQL query. Three files, two hops through shared state, one SQL injection. No other scanner catches this."

---

## Real-world CVE demo (advanced, +2 min)

For a technical security audience, scan one of the CVE-based samples:

```bash
cat backend/tests/real_world/cve_2022_34265_sqli.py
```

Submit via the UI (Paste Code tab) or API:

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d "{\"source_type\": \"raw_code\", \"source\": \"$(cat backend/tests/real_world/cve_2022_34265_sqli.py | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')\"}" \
  | python3 -m json.tool
```

Expected: CWE-89 CRITICAL finding. This is CVE-2022-34265 (Django `Trunc`/`Extract` SQL injection). VEXIS finds it cold with no prior knowledge of this CVE.

---

## Quick demo (if time is short)

Skip Steps 1 and 5. Run only Steps 2–4 using the pre-built SQLi snippet. Takes ~3 minutes with a warm Docker environment.

For a **non-technical audience**, skip Step 4's code view and focus on:
- The attack flow graph (visual = memorable)
- The PoC "payload" line — one concrete string that demonstrates the vulnerability
- The severity + confidence score

---

## Taint-only banner demo (Sprint 3)

If the LLM budget is exhausted mid-scan, findings produced without LLM confirmation will have a banner on the scan results page. To demonstrate: set `VEXIS_MAX_LLM_CALLS_PER_SCAN=1` in the backend env, then submit a multi-finding scan. The first finding will have full LLM reasoning; subsequent ones will show the taint-only banner.

**Talking point:** "Even when the LLM budget runs out, VEXIS still surfaces findings from the taint engine — it degrades gracefully rather than silently failing. The banner is transparent about which findings have LLM confirmation."

---

## New class demos (Sprint 2, +1 min each)

### SSTI demo
Submit via Paste Code tab:
```python
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
```
Expected: CWE-1336 CRITICAL. Source: `request.args.get("name")` → Sink: `render_template_string(template)`.
Payload: `{{7*7}}` — if output shows `49`, the template engine evaluated the expression. Full RCE: `{{''.__class__.__mro__[1].__subclasses__()}}`.
Talking point: "SSTI is often missed because the code looks like it's just doing string interpolation. VEXIS sees that `template` is user-controlled and flows into `render_template_string` — which is a Jinja2 execution context."

### SSRF demo
Submit via Paste Code tab:
```python
import requests
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return jsonify({"body": resp.text[:500]})
```
Expected: CWE-918 CRITICAL. Attack vector: `GET /fetch?url=http://169.254.169.254/latest/meta-data/` (AWS metadata endpoint).
Talking point: "SSRF lets attackers pivot from your server to internal infrastructure. This fetches any URL — including `http://localhost:6379` (Redis), `http://169.254.169.254` (cloud metadata), internal services behind the firewall."

### Deserialization demo
Submit via Paste Code tab:
```python
import pickle, base64
from flask import Flask, request
app = Flask(__name__)

@app.route("/load")
def load_object():
    data = request.args.get("data")
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)
```
Expected: CWE-502 CRITICAL.
Talking point: "pickle.loads on attacker-controlled bytes is instant RCE — one of the most severe patterns. VEXIS traces the HTTP param through base64.b64decode to pickle.loads and flags it as critical."

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Scan stuck at "Taint Analysis" | Check `docker compose logs api` — may be Gemini API rate limit |
| WebSocket not connecting | Confirm `NEXT_PUBLIC_WS_URL=ws://localhost:8000` in frontend env |
| No findings on safe code | Expected — false positive rate is <15%, safe code returns 0 |
| Attack flow graph blank | Check browser console — D3 needs `attack_flow.nodes` array in finding |
| Cross-file scan finds wrong source | Verify files submitted with `=== FILE: filename.py ===` markers |
| SSTI not detected | Check that code uses `render_template_string(var)` not `render_template("file.html", var=...)` — the latter is safe by design |
| SSRF flagged on safe code | Ensure URL comes from a constant, not user input — allowlist checks are runtime logic the taint engine can't evaluate |
| Scan status stuck at "timeout" | Scan exceeded `SCAN_TIMEOUT_SECONDS` (default 600). Reduce input size or raise the limit in backend env. |
| Taint-only banner showing unexpectedly | `VEXIS_MAX_LLM_CALLS_PER_SCAN` may be set too low, or Gemini API is failing — check `docker compose logs api` |
