"""
Cross-file taint tracking test suite.
Run from repo root: python -X utf8 backend/tests/run_cross_file.py

Tests 3 scenarios using multi-file raw_code submission (=== FILE: markers).
"""
import json
import os
import sys
import time
from pathlib import Path

try:
    import httpx
    _HTTP = httpx.Client(timeout=30)
except ImportError:
    import subprocess
    _HTTP = None

BASE = "http://localhost:8000"
SAMPLES = Path(__file__).parent / "vulnerable_samples" / "cross_file"

# Multi-file separator format
def build_multifile(files: dict[str, str]) -> str:
    """Build a multi-file raw_code payload from {filename: content} dict."""
    parts = []
    for name, content in files.items():
        parts.append(f"# === FILE: {name} ===\n{content}")
    return "\n\n".join(parts)


def load_dir(path: Path) -> dict[str, str]:
    return {f.name: f.read_text(encoding="utf-8") for f in sorted(path.glob("*.py"))}


CORPUS = [
    dict(
        name="golden_test",
        dir="golden_test",
        expected_cwe="CWE-89",
        expected_severity="critical",
        expected_source_file="rate_limiter.py",
        expected_sink_file="logger.py",
        description="X-Client-ID header -> request.state -> log_search() -> raw SQL (3-file)",
        expected_min=1,
        no_fp_check=True,  # parameterized query in search.py must NOT be flagged as vuln
    ),
    dict(
        name="session_poison",
        dir="session_poison",
        expected_cwe="CWE-78",
        expected_severity="critical",
        expected_source_file="login.py",
        expected_sink_file="admin.py",
        description="request.form -> session['user'] -> os.system (session poisoning)",
        expected_min=1,
    ),
    dict(
        name="return_value",
        dir="return_value",
        expected_cwe="CWE-78",
        expected_severity="critical",
        expected_source_file="utils.py",
        expected_sink_file="handler.py",
        description="request.args.get() returned from utils.py -> subprocess.run in handler.py",
        expected_min=1,
    ),
]


def post(path: str, body: dict) -> dict:
    if _HTTP is not None:
        return _HTTP.post(f"{BASE}{path}", json=body).json()
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
    print("=" * 72)
    print("VEXIS Cross-File Taint Tracking Tests")
    print("=" * 72)
    print()

    scan_ids: dict[str, str] = {}
    for sample in CORPUS:
        files = load_dir(SAMPLES / sample["dir"])
        code = build_multifile(files)
        resp = post("/api/v1/scan", {"source_type": "raw_code", "source": code})
        if "id" not in resp:
            print(f"  ERROR submitting {sample['name']}: {resp}")
            sys.exit(1)
        scan_ids[sample["name"]] = resp["id"]
        print(f"  {sample['name']:20s} -> {resp['id']}")
        print(f"  {'':20s}    {sample['description']}")

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

    print()
    print("=" * 72)
    print(f"{'Test':<22} {'CWE':<10} {'Src file':<18} {'Sink file':<18} Status")
    print("-" * 72)

    passed = failed = 0

    for sample in CORPUS:
        name = sample["name"]
        if name not in done:
            print(f"{name:<22} {'TIMEOUT':<10} {'':18} {'':18} FAIL")
            failed += 1
            continue

        result = done[name]
        sid = scan_ids[name]

        if result["status"] == "failed":
            print(f"{name:<22} {'ERR':<10} {'':18} {'':18} FAIL (scan error: {result.get('error_message','')[:30]})")
            failed += 1
            continue

        fr = get(f"/api/v1/scan/{sid}/findings")
        findings = fr.get("findings", [])
        got = len(findings)

        ok = True
        issues = []
        exp_cwe = sample["expected_cwe"]
        exp_sf = sample.get("expected_source_file", "")
        exp_tk = sample.get("expected_sink_file", "")

        def _matches(f: dict) -> bool:
            """Return True if finding satisfies all expected criteria."""
            if f.get("cwe_id") != exp_cwe:
                return False
            if exp_sf and Path(f.get("source_file", "")).name != exp_sf:
                return False
            if exp_tk and Path(f.get("sink_file", "")).name != exp_tk:
                return False
            return True

        if got < sample["expected_min"]:
            ok = False
            issues.append(f"no findings (got {got})")
            display_f: dict = {}
        else:
            display_f = next((f for f in findings if _matches(f)), findings[0])
            if not _matches(display_f):
                ok = False
                best = findings[0]
                if best.get("cwe_id") != exp_cwe:
                    issues.append(f"no finding with CWE={exp_cwe} (best: {best.get('cwe_id')})")
                elif exp_sf and Path(best.get("source_file", "")).name != exp_sf:
                    issues.append(f"no finding src={exp_sf} (best: {Path(best.get('source_file','')).name})")
                elif exp_tk and Path(best.get("sink_file", "")).name != exp_tk:
                    issues.append(f"no finding sink={exp_tk} (best: {Path(best.get('sink_file','')).name})")

        cwe_str = display_f.get("cwe_id", "-") if display_f else "-"
        sf_str = Path(display_f.get("source_file", "-")).name if display_f else "-"
        tk_str = Path(display_f.get("sink_file", "-")).name if display_f else "-"
        status = "PASS" if ok else "FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        issue_str = f"  <- {'; '.join(issues)}" if issues else ""
        print(f"{name:<22} {cwe_str:<10} {sf_str:<18} {tk_str:<18} {status}{issue_str}")

    print("=" * 72)
    total = passed + failed
    print(f"\n{passed}/{total} passed", end="")
    if failed == 0:
        print(" ✓ All cross-file tests passed!")
    else:
        print(f" — {failed} failure{'s' if failed > 1 else ''}")
    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
