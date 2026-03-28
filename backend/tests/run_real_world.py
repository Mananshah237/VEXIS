"""
Real-world CVE validation — scans 3 CVE-based samples through the VEXIS API.
Run from repo root: python -X utf8 backend/tests/run_real_world.py

CVEs tested:
  CVE-2022-34265  SQL Injection    (Django Trunc/Extract — Django 3.2.x/4.0.x)
  CVE-2023-30553  Command Injection (Archery SQL audit platform v1.9.0)
  CVE-2023-47890  Path Traversal   (pyLoad download manager < 0.5.0b3.dev75)

Sources:
  CVE-2022-34265: https://github.com/advisories/GHSA-p64x-8rxx-wf6q
  CVE-2023-30553: https://github.com/hhyo/Archery/security/advisories/GHSA-hvcq-r2r2-34ch
  CVE-2023-47890: https://github.com/pyload/pyload/security/advisories/GHSA-h73m-pcfw-25h2
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE = "http://localhost:8000"
REAL_WORLD_DIR = Path(__file__).parent / "real_world"

CORPUS = [
    dict(
        name="CVE-2022-34265",
        file="cve_2022_34265_sqli.py",
        cwe="CWE-89",
        severity_min="critical",
        description="SQL Injection via Trunc/Extract kind param (Django 3.2/4.0)",
        expected_min=1,
    ),
    dict(
        name="CVE-2023-30553",
        file="cve_2023_30553_cmdi.py",
        cwe="CWE-78",
        severity_min="critical",
        description="Command Injection via db_name param (Archery SQL audit v1.9.0)",
        expected_min=1,
    ),
    dict(
        name="CVE-2023-47890",
        file="cve_2023_47890_path_traversal.py",
        cwe="CWE-22",
        severity_min="high",
        description="Path Traversal via bypass-able sanitizer (pyLoad < 0.5.0b3.dev75)",
        expected_min=1,
    ),
]


def post(path: str, body: dict) -> dict:
    import tempfile
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
    r = subprocess.run(["curl", "-s", f"{BASE}{path}"], capture_output=True, text=True)
    return json.loads(r.stdout)


SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def meets_min_severity(actual: str, minimum: str) -> bool:
    try:
        return SEV_ORDER.index(actual.lower()) <= SEV_ORDER.index(minimum.lower())
    except ValueError:
        return False


def main() -> None:
    print("=" * 72)
    print("VEXIS Real-World CVE Validation")
    print("=" * 72)
    print()

    # Submit all scans
    print(f"Submitting {len(CORPUS)} CVE-based scans...")
    scan_ids: dict[str, str] = {}
    for sample in CORPUS:
        code = (REAL_WORLD_DIR / sample["file"]).read_text(encoding="utf-8")
        resp = post("/api/v1/scan", {"source_type": "raw_code", "source": code})
        if "id" not in resp:
            print(f"  ERROR submitting {sample['name']}: {resp}")
            sys.exit(1)
        scan_ids[sample["name"]] = resp["id"]
        print(f"  {sample['name']:20s} {sample['description'][:45]}")
        print(f"  {'':20s} -> {resp['id']}")

    # Poll until done (max 10 min)
    print("\nPolling (up to 10 min)...")
    done: dict[str, dict] = {}
    for _ in range(120):
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

    # Results table
    print()
    print("=" * 72)
    header = f"{'CVE':<20} {'Expected CWE':<12} {'Got':<4} {'Severity':<10} {'Status'}"
    print(header)
    print("-" * 72)

    passed = 0
    failed = 0
    results_for_readme: list[dict] = []

    for sample in CORPUS:
        name = sample["name"]

        if name not in done:
            print(f"{name:<20} {sample['cwe']:<12} {'?':>4} {'TIMEOUT':<10} FAIL")
            failed += 1
            continue

        result = done[name]
        sid = scan_ids[name]

        if result["status"] == "failed":
            print(f"{name:<20} {sample['cwe']:<12} {'ERR':>4} {'':10} FAIL (scan error)")
            failed += 1
            continue

        findings_resp = get(f"/api/v1/scan/{sid}/findings")
        findings = findings_resp.get("findings", [])
        got_count = len(findings)
        first = findings[0] if findings else None

        ok = got_count >= sample["expected_min"]
        cwe_match = first and first.get("cwe_id") == sample["cwe"] if ok else False
        if ok and not cwe_match:
            ok = False

        severity = first["severity"].upper() if first else "-"
        got_cwe = first.get("cwe_id", "-") if first else "-"
        status_str = "PASS" if ok else "FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        issue = ""
        if not findings:
            issue = " ← no findings"
        elif not cwe_match:
            issue = f" ← wrong CWE: {got_cwe}"

        print(f"{name:<20} {sample['cwe']:<12} {got_count:>4} {severity:<10} {status_str}{issue}")

        results_for_readme.append({
            "cve": name,
            "description": sample["description"],
            "cwe": sample["cwe"],
            "findings": got_count,
            "severity": severity if findings else "—",
            "passed": ok,
        })

    print("=" * 72)
    total = passed + failed
    print(f"\n{passed}/{total} CVEs correctly detected", end="")
    if failed == 0:
        print(" ✓ All real-world CVEs detected!")
    else:
        print(f" — {failed} failure{'s' if failed > 1 else ''}")
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
