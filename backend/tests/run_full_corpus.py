"""
Full corpus test — scans all 21 samples through the API and validates findings.
Run from repo root: python backend/tests/run_full_corpus.py

Samples:
  Vulnerable (expect ≥1 finding with correct CWE):
    sqli_fstring, sqli_concat, sqli_partial_sanitizer, sqli_orm_raw_fallback,
    cmdi_subprocess, cmdi_eval, path_trav_join, path_trav_send_file,
    ssti_basic, ssrf_requests_get, deser_pickle_loads, xss_reflected,
    cmdi_os_system, path_trav_open, sqli_raw_concat

  Safe (expect 0 findings — false positive checks):
    safe_parameterized_query, safe_shlex_quote, safe_render_template,
    safe_hardcoded_url, safe_yaml_load, safe_escaped_xss, safe_cmdi_shlex
"""
import json
import os
import sys
import time
from pathlib import Path

try:
    import httpx
    _HTTP = httpx.Client(timeout=60)
except ImportError:
    import subprocess
    _HTTP = None

BASE = "http://localhost:8000"
SAMPLES_DIR = Path(__file__).parent / "vulnerable_samples"

# Inline code for the 4 original E2E payloads
_INLINE: dict[str, str] = {
    "sqli_fstring": (
        "import sqlite3\nfrom flask import request\n\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    db = sqlite3.connect('app.db')\n"
        "    db.execute(f\"SELECT * FROM items WHERE name = '{q}'\")\n"
        "    return 'ok'\n"
    ),
    "sqli_concat": (
        "import sqlite3\nfrom flask import request\n\n"
        "@app.route('/user')\n"
        "def get_user():\n"
        "    user_id = request.args.get('id')\n"
        "    db = sqlite3.connect('app.db')\n"
        "    db.execute(\"SELECT * FROM users WHERE id=\" + user_id)\n"
        "    return 'ok'\n"
    ),
    "cmdi_subprocess": (
        "import subprocess\nfrom flask import request\n\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)\n"
        "    return result.stdout.decode()\n"
    ),
    "path_trav_join": (
        "import os\nfrom flask import request, send_file\n\n"
        "SAFE_DIR = '/var/app/files'\n\n"
        "@app.route('/download')\n"
        "def download():\n"
        "    filename = request.args.get('filename')\n"
        "    full_path = os.path.join(SAFE_DIR, filename)\n"
        "    return send_file(full_path)\n"
    ),
}

# File-based samples: name → (relative_path, expected_findings, expected_cwe)
CORPUS: list[dict] = [
    # --- Vulnerable samples (14) ---
    # SQL Injection
    dict(name="sqli_fstring",            code=_INLINE["sqli_fstring"],               expected=1, cwe="CWE-89"),
    dict(name="sqli_concat",             code=_INLINE["sqli_concat"],                expected=1, cwe="CWE-89"),
    dict(name="sqli_partial_sanitizer",  file="sqli/partial_sanitizer.py",           expected=1, cwe="CWE-89"),
    dict(name="sqli_orm_raw_fallback",   file="sqli/orm_raw_fallback.py",            expected=1, cwe="CWE-89"),
    # Command Injection
    dict(name="cmdi_subprocess",         code=_INLINE["cmdi_subprocess"],            expected=1, cwe="CWE-78"),
    dict(name="cmdi_eval",               file="cmdi/eval_input.py",                  expected=1, cwe="CWE-78"),
    dict(name="cmdi_os_system",          file="cmdi/os_system.py",                   expected=1, cwe="CWE-78"),
    # Path Traversal
    dict(name="path_trav_join",          code=_INLINE["path_trav_join"],             expected=1, cwe="CWE-22"),
    dict(name="path_trav_send_file",     file="path_traversal/send_file_direct.py",  expected=1, cwe="CWE-22"),
    dict(name="path_trav_open",          file="path_traversal/open_direct.py",       expected=1, cwe="CWE-22"),
    # SSTI
    dict(name="ssti_template_string",    file="ssti/basic_template_string.py",       expected=1, cwe="CWE-1336"),
    # SSRF
    dict(name="ssrf_requests_get",       file="ssrf/requests_get.py",                expected=1, cwe="CWE-918"),
    # Deserialization
    dict(name="deser_pickle_loads",      file="deserialization/pickle_loads.py",     expected=1, cwe="CWE-502"),
    # XSS
    dict(name="xss_reflected_markup",    file="xss/reflected_basic.py",              expected=1, cwe="CWE-79"),

    # --- Safe samples (7 false positive checks) ---
    dict(name="safe_parameterized",      file="safe/parameterized_query.py",         expected=0, cwe=None),
    dict(name="safe_shlex_quote",        file="safe/shlex_quote.py",                 expected=0, cwe=None),
    dict(name="safe_render_template",    file="ssti/safe_render_template.py",        expected=0, cwe=None),
    dict(name="safe_hardcoded_url",      file="ssrf/safe_allowlist.py",              expected=0, cwe=None),
    dict(name="safe_yaml_load",          file="deserialization/safe_yaml.py",        expected=0, cwe=None),
    dict(name="safe_escaped_xss",        file="xss/safe_escaped.py",                expected=0, cwe=None),
    dict(name="safe_cmdi_shlex",          file="cmdi/safe_shlex.py",                  expected=0, cwe=None),

    # --- JS/TS samples (7 vulnerable + 3 safe) ---
    dict(name="js_sqli_template",        file="js/sqli_template_literal.js",    expected=1, cwe="CWE-89"),
    dict(name="js_cmdi_exec",            file="js/cmdi_exec.js",                expected=1, cwe="CWE-78"),
    dict(name="js_path_trav_sendfile",   file="js/path_traversal_sendfile.js",  expected=1, cwe="CWE-22"),
    dict(name="js_xss_res_send",         file="js/xss_res_send.js",             expected=1, cwe="CWE-79"),
    dict(name="js_ssrf_fetch",           file="js/ssrf_fetch.js",               expected=1, cwe="CWE-918"),
    dict(name="js_deser_unserialize",    file="js/deser_unserialize.js",        expected=1, cwe="CWE-502"),
    dict(name="js_ssti_ejs",             file="js/ssti_ejs.js",                 expected=1, cwe="CWE-1336"),
    dict(name="js_safe_parameterized",   file="js/safe_parameterized.js",       expected=0, cwe=None),
    dict(name="js_safe_execfile",        file="js/safe_execfile.js",            expected=0, cwe=None),
    dict(name="js_safe_dompurify",       file="js/safe_dompurify.js",           expected=0, cwe=None),
    # Context-sensitive sanitizer test
    dict(name="ctx_escape_to_sql",       file="context_sanitizer/escape_to_sql.py", expected=1, cwe="CWE-89"),

    # --- Second-order injection (2 samples) ---
    dict(name="so_stored_sqli",          file="second_order/stored_sqli.py",        expected=1, cwe="CWE-89"),
    dict(name="so_stored_xss",           file="second_order/stored_xss.py",         expected=1, cwe="CWE-79"),

    # --- New vuln classes: CWE-601 / 117 / 90 / 611 / 362 / 287 (6 vuln + 5 safe) ---
    dict(name="redirect_open",           file="redirect/open_redirect.py",           expected=1, cwe="CWE-601"),
    dict(name="redirect_safe",           file="redirect/safe_redirect.py",           expected=0, cwe=None),
    dict(name="log_injection_basic",     file="log_injection/basic.py",              expected=1, cwe="CWE-117"),
    dict(name="log_injection_safe",      file="log_injection/safe_sanitized.py",     expected=0, cwe=None),
    dict(name="ldap_injection_basic",    file="ldap/basic_search.py",               expected=1, cwe="CWE-90"),
    dict(name="ldap_safe",               file="ldap/safe_escaped.py",               expected=0, cwe=None),
    dict(name="xxe_basic",               file="xxe/basic_parse.py",                 expected=1, cwe="CWE-611"),
    dict(name="xxe_safe",                file="xxe/safe_defused.py",                expected=0, cwe=None),
    dict(name="race_toctou",             file="race/toctou_file.py",                expected=1, cwe="CWE-362"),
    dict(name="auth_bypass",             file="auth/bypass_no_decorator.py",        expected=1, cwe="CWE-287"),
    dict(name="auth_safe",               file="auth/safe_protected.py",             expected=0, cwe=None),
]


def _get_code(sample: dict) -> str:
    if "code" in sample:
        return sample["code"]
    path = SAMPLES_DIR / sample["file"]
    return path.read_text(encoding="utf-8")


def post(path: str, body: dict) -> dict:
    if _HTTP is not None:
        r = _HTTP.post(f"{BASE}{path}", json=body)
        return r.json()
    import subprocess, tempfile, os
    body_bytes = json.dumps(body).encode()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        f.write(body_bytes)
        tmp = f.name
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", f"{BASE}{path}",
             "-H", "Content-Type: application/json",
             "--data-binary", f"@{tmp}"],
            capture_output=True, text=True,
        )
        return json.loads(r.stdout)
    finally:
        os.unlink(tmp)


def get(path: str) -> dict:
    if _HTTP is not None:
        return _HTTP.get(f"{BASE}{path}").json()
    import subprocess
    r = subprocess.run(["curl", "-s", f"{BASE}{path}"], capture_output=True, text=True)
    return json.loads(r.stdout)


def main() -> None:
    print("=" * 70)
    print("VEXIS Full Corpus Test")
    print("=" * 70)

    # Submit all scans
    print(f"\nSubmitting {len(CORPUS)} scans...")
    scan_ids: dict[str, str] = {}
    for sample in CORPUS:
        code = _get_code(sample)
        for attempt in range(3):
            try:
                resp = post("/api/v1/scan", {"source_type": "raw_code", "source": code})
                break
            except Exception as exc:
                if attempt == 2:
                    print(f"  ERROR submitting {sample['name']}: {exc}")
                    sys.exit(1)
                time.sleep(2)
        if "id" not in resp:
            print(f"  ERROR submitting {sample['name']}: {resp}")
            sys.exit(1)
        scan_ids[sample["name"]] = resp["id"]
        print(f"  {sample['name']:35s} -> {resp['id']}")
        time.sleep(1.5)  # stagger submissions to avoid LLM API congestion (32 scans)

    # Poll until all complete (max 20 min for 45-sample corpus)
    print("\nPolling (up to 20 min)...")
    done: dict[str, dict] = {}
    for _ in range(240):
        time.sleep(5)
        for name, sid in scan_ids.items():
            if name in done:
                continue
            d = get(f"/api/v1/scan/{sid}")
            if d.get("status") in ("complete", "failed"):
                done[name] = d
                print(f"  done: {name} [{d['status']}]")
        if len(done) == len(scan_ids):
            break

    # Evaluate results
    print("\n" + "=" * 70)
    header = f"{'Sample':<35} {'Exp':>4} {'Got':>4} {'CWE':<10} {'Severity':<10} Status"
    print(header)
    print("-" * 70)

    passed = 0
    failed = 0

    for sample in CORPUS:
        name = sample["name"]
        expected_count = sample["expected"]
        expected_cwe = sample["cwe"]

        if name not in done:
            print(f"{name:<35} {'?':>4} {'?':>4} {'TIMEOUT':<10} {'':10} TIMEOUT")
            failed += 1
            continue

        result = done[name]
        sid = scan_ids[name]

        if result["status"] == "failed":
            print(f"{name:<35} {expected_count:>4} {'ERR':>4} {'':10} {'':10} FAIL (scan error: {result.get('error_message', '')[:40]})")
            failed += 1
            continue

        findings_resp = get(f"/api/v1/scan/{sid}/findings")
        findings = findings_resp.get("findings", [])
        got_count = len(findings)

        # For vulnerable samples: check count ≥ expected and CWE matches
        # For safe samples: check count == 0
        ok = True
        issues = []

        if expected_count == 0:
            # False positive check
            if got_count != 0:
                ok = False
                cwes = [f.get("cwe_id") for f in findings]
                issues.append(f"FALSE POSITIVE: got {got_count} findings {cwes}")
        else:
            if got_count == 0:
                ok = False
                issues.append("no findings")
            else:
                if expected_cwe and findings[0].get("cwe_id") != expected_cwe:
                    ok = False
                    issues.append(f"wrong CWE: {findings[0].get('cwe_id')} ≠ {expected_cwe}")

        severity = findings[0]["severity"].upper() if findings else "-"
        cwe_str = findings[0].get("cwe_id", "-") if findings else (expected_cwe or "-")
        status_str = "PASS" if ok else "FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        issues_str = f"  ← {'; '.join(issues)}" if issues else ""
        print(f"{name:<35} {expected_count:>4} {got_count:>4} {cwe_str:<10} {severity:<10} {status_str}{issues_str}")

    print("=" * 70)
    total = passed + failed
    print(f"\n{passed}/{total} passed", end="")
    if failed == 0:
        print(" ✓ All tests passed!")
    else:
        print(f" — {failed} failure{'s' if failed > 1 else ''}")
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
