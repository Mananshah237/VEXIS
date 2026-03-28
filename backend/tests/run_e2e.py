"""
E2E smoke test — submits 4 vulnerable samples and validates findings.
Run from repo root: python backend/tests/run_e2e.py
"""
import json
import subprocess
import sys
import time

BASE = "http://localhost:8000"

PAYLOADS = {
    "sqli_fstring": (
        "import sqlite3\n"
        "from flask import request\n\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    db = sqlite3.connect('app.db')\n"
        "    db.execute(f\"SELECT * FROM items WHERE name = '{q}'\")\n"
        "    return 'ok'\n"
    ),
    "sqli_concat": (
        "import sqlite3\n"
        "from flask import request\n\n"
        "@app.route('/user')\n"
        "def get_user():\n"
        "    user_id = request.args.get('id')\n"
        "    db = sqlite3.connect('app.db')\n"
        "    db.execute(\"SELECT * FROM users WHERE id=\" + user_id)\n"
        "    return 'ok'\n"
    ),
    "cmdi": (
        "import subprocess\n"
        "from flask import request\n\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)\n"
        "    return result.stdout.decode()\n"
    ),
    "path_trav": (
        "import os\n"
        "from flask import request, send_file\n\n"
        "SAFE_DIR = '/var/app/files'\n\n"
        "@app.route('/download')\n"
        "def download():\n"
        "    filename = request.args.get('filename')\n"
        "    full_path = os.path.join(SAFE_DIR, filename)\n"
        "    return send_file(full_path)\n"
    ),
}

EXPECTED_CWE = {
    "sqli_fstring": "CWE-89",
    "sqli_concat":  "CWE-89",
    "cmdi":         "CWE-78",
    "path_trav":    "CWE-22",
}


def get(path: str) -> dict:
    r = subprocess.run(["curl", "-s", f"{BASE}{path}"], capture_output=True, text=True)
    return json.loads(r.stdout)


def post(path: str, body: dict) -> dict:
    import tempfile, os
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


def main():
    print("Submitting scans...")
    scan_ids = {}
    for name, code in PAYLOADS.items():
        d = post("/api/v1/scan", {"source_type": "raw_code", "source": code})
        scan_ids[name] = d["id"]
        print(f"  {name}: {d['id']}")

    print("\nPolling (up to 3 min)...")
    done: dict[str, dict] = {}
    for _ in range(36):
        time.sleep(5)
        for name, sid in scan_ids.items():
            if name in done:
                continue
            d = get(f"/api/v1/scan/{sid}")
            if d["status"] in ("complete", "failed"):
                done[name] = d
        if len(done) == len(scan_ids):
            break

    print("\n" + "=" * 60)
    passed = 0
    failed = 0
    for name, result in done.items():
        sid = scan_ids[name]
        findings_resp = get(f"/api/v1/scan/{sid}/findings")
        findings = findings_resp.get("findings", [])

        ok = True
        issues = []
        if result["status"] != "complete":
            ok = False
            issues.append(f"scan status={result['status']} err={result.get('error_message')}")
        if not findings:
            ok = False
            issues.append("no findings")
        else:
            f = findings[0]
            if f["cwe_id"] != EXPECTED_CWE[name]:
                ok = False
                issues.append(f"wrong CWE: got {f['cwe_id']} expected {EXPECTED_CWE[name]}")
            if not f["attack_flow"]["nodes"]:
                ok = False
                issues.append("attack_flow.nodes is empty")
            if not f["taint_path"]["path"]:
                ok = False
                issues.append("taint_path.path is empty")

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
            f = findings[0]
            print(f"[{status}] {name}")
            print(f"       [{f['severity'].upper()}] {f['cwe_id']} conf={f['confidence']:.2f}")
            print(f"       attack_flow: {len(f['attack_flow']['nodes'])} nodes, {len(f['attack_flow']['edges'])} edges")
            print(f"       payload: {(f.get('poc') or {}).get('payload', 'N/A')[:80]}")
        else:
            failed += 1
            print(f"[{status}] {name}: {'; '.join(issues)}")

    print(f"\n{passed}/{len(done)} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
