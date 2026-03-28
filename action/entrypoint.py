#!/usr/bin/env python3
"""
VEXIS GitHub Action entrypoint.

Collects source files, submits them to the VEXIS API, polls for completion,
and emits GitHub Actions workflow commands for annotations and outputs.
"""
import os
import sys
import time
import json
from pathlib import Path

import httpx

# ── Config from environment ─────────────────────────────────────────────────
API_URL = os.environ["VEXIS_API_URL"].rstrip("/")
API_KEY = os.environ["VEXIS_API_KEY"]
THRESHOLD = os.environ.get("VEXIS_SEVERITY_THRESHOLD", "high").lower()
SCAN_PATH = os.environ.get("VEXIS_SCAN_PATH", ".")
LANGUAGES = [l.strip().lower() for l in os.environ.get("VEXIS_LANGUAGES", "python,javascript").split(",")]
TIMEOUT = int(os.environ.get("VEXIS_TIMEOUT", "300"))
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_WORKSPACE = os.environ.get("GITHUB_WORKSPACE", ".")

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
THRESHOLD_RANK = SEVERITY_RANK.get(THRESHOLD, 3)

LANG_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx"],
}


def gha_log(level: str, msg: str) -> None:
    """Emit a GitHub Actions log command."""
    print(f"::{level}::{msg}", flush=True)


def gha_annotation(level: str, file: str, line: int, msg: str) -> None:
    """Emit a file annotation (error/warning/notice)."""
    print(f"::{level} file={file},line={line}::{msg}", flush=True)


def set_output(name: str, value: str) -> None:
    """Write a step output via GITHUB_OUTPUT file (new method) or fallback."""
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}", flush=True)


def collect_source(scan_root: Path) -> str:
    """Collect all source files matching LANGUAGES and return as multi-file raw_code."""
    extensions = []
    for lang in LANGUAGES:
        extensions.extend(LANG_EXTENSIONS.get(lang, []))

    parts = []
    file_count = 0
    for ext in extensions:
        for fpath in sorted(scan_root.rglob(f"*{ext}")):
            # Skip vendored/generated paths
            skip_parts = {"node_modules", ".venv", "venv", "__pycache__", ".git",
                          "dist", "build", ".next", "coverage"}
            if any(p in fpath.parts for p in skip_parts):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                rel = fpath.relative_to(scan_root)
                parts.append(f"# === FILE: {rel} ===\n{content}")
                file_count += 1
            except Exception as e:
                gha_log("warning", f"Could not read {fpath}: {e}")

    if not parts:
        gha_log("warning", f"No source files found in {scan_root} for languages: {LANGUAGES}")
        return ""

    gha_log("notice", f"Collected {file_count} files ({', '.join(LANGUAGES)})")
    return "\n\n".join(parts)


def submit_scan(source_code: str) -> str | None:
    """Submit scan to VEXIS API. Returns scan_id or None."""
    headers = {"X-VEXIS-API-Key": API_KEY, "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{API_URL}/api/v1/scan",
                json={"source_type": "raw_code", "source": source_code},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("id")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            gha_log("error", "VEXIS rate limit reached. Upgrade your plan for unlimited scans.")
        else:
            gha_log("error", f"VEXIS API error {e.response.status_code}: {e.response.text[:200]}")
        return None
    except Exception as e:
        gha_log("error", f"Failed to submit scan: {e}")
        return None


def poll_scan(scan_id: str) -> dict | None:
    """Poll until scan is complete or times out."""
    headers = {"X-VEXIS-API-Key": API_KEY}
    deadline = time.time() + TIMEOUT
    gha_log("notice", f"Polling scan {scan_id} (timeout: {TIMEOUT}s)...")

    with httpx.Client(timeout=15) as client:
        while time.time() < deadline:
            try:
                resp = client.get(f"{API_URL}/api/v1/scan/{scan_id}", headers=headers)
                data = resp.json()
                status = data.get("status", "unknown")

                if status == "complete":
                    gha_log("notice", f"Scan complete.")
                    return data
                elif status == "failed":
                    gha_log("error", f"Scan failed: {data.get('error_message', 'unknown error')}")
                    return None
                elif status == "timeout":
                    gha_log("error", "Scan timed out on the server.")
                    return None

                gha_log("notice", f"  {status}...")
                time.sleep(5)
            except Exception as e:
                gha_log("warning", f"Polling error: {e}")
                time.sleep(5)

    gha_log("error", f"Action timed out after {TIMEOUT}s waiting for scan.")
    return None


def fetch_findings(scan_id: str) -> list[dict]:
    """Fetch all findings for a completed scan."""
    headers = {"X-VEXIS-API-Key": API_KEY}
    findings = []
    page = 1
    with httpx.Client(timeout=15) as client:
        while True:
            try:
                resp = client.get(
                    f"{API_URL}/api/v1/scan/{scan_id}/findings",
                    params={"page": page, "per_page": 100},
                    headers=headers,
                )
                data = resp.json()
                batch = data.get("findings", [])
                findings.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
            except Exception as e:
                gha_log("warning", f"Failed to fetch findings page {page}: {e}")
                break
    return findings


def print_summary_table(findings: list[dict], scan_id: str) -> None:
    """Print a formatted table of findings to the Actions log."""
    print("\n" + "=" * 80, flush=True)
    print("VEXIS Security Scan Results", flush=True)
    print("=" * 80, flush=True)

    if not findings:
        print("No vulnerabilities found.", flush=True)
        print("=" * 80, flush=True)
        return

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.get("severity", "unknown")] = sev_counts.get(f.get("severity", "unknown"), 0) + 1

    print(f"\nSummary: {len(findings)} finding(s)", flush=True)
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        if count:
            indicator = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "🔵"
            print(f"  {indicator} {sev.upper()}: {count}", flush=True)

    print(f"\n{'Severity':<10} {'CWE':<10} {'File':<35} {'Line':<6} {'Title'}", flush=True)
    print("-" * 80, flush=True)
    for f in sorted(findings, key=lambda x: SEVERITY_RANK.get(x.get("severity", ""), 0), reverse=True):
        sev = f.get("severity", "?").upper()[:8]
        cwe = f.get("cwe_id", "?")[:9]
        src_file = (f.get("source_file") or "?").split("/")[-1][:34]
        src_line = str(f.get("source_line") or "?")[:5]
        title = (f.get("title") or "")[:45]
        print(f"{sev:<10} {cwe:<10} {src_file:<35} {src_line:<6} {title}", flush=True)

    print("=" * 80, flush=True)
    print(f"Full report: {API_URL.replace('/api', '')}/scan/{scan_id}", flush=True)
    print("=" * 80 + "\n", flush=True)


def main() -> int:
    scan_root = Path(GITHUB_WORKSPACE) / SCAN_PATH
    if not scan_root.is_dir():
        gha_log("error", f"Scan path does not exist: {scan_root}")
        return 1

    # Step 1: Collect source
    source_code = collect_source(scan_root)
    if not source_code:
        gha_log("notice", "No source files found — skipping scan.")
        set_output("scan-id", "")
        set_output("findings-count", "0")
        set_output("critical-count", "0")
        set_output("high-count", "0")
        return 0

    # Step 2: Submit scan
    gha_log("notice", f"Submitting scan to {API_URL}...")
    scan_id = submit_scan(source_code)
    if not scan_id:
        return 1

    gha_log("notice", f"Scan submitted: {scan_id}")
    set_output("scan-id", scan_id)
    set_output("report-url", f"{API_URL.replace('/api', '')}/scan/{scan_id}")

    # Step 3: Poll for completion
    scan = poll_scan(scan_id)
    if not scan:
        return 1

    # Step 4: Fetch findings
    findings = fetch_findings(scan_id)
    set_output("findings-count", str(len(findings)))
    set_output("critical-count", str(sum(1 for f in findings if f.get("severity") == "critical")))
    set_output("high-count", str(sum(1 for f in findings if f.get("severity") == "high")))

    # Step 5: Print summary table
    print_summary_table(findings, scan_id)

    # Step 6: Emit GitHub annotations
    for f in findings:
        sev_rank = SEVERITY_RANK.get(f.get("severity", "info"), 0)
        annotation_level = "error" if sev_rank >= SEVERITY_RANK.get("high", 3) else "warning"

        src_file = f.get("source_file") or ""
        # Make path relative to workspace
        if src_file.startswith("/"):
            try:
                src_file = str(Path(src_file).relative_to(GITHUB_WORKSPACE))
            except ValueError:
                pass

        msg = (
            f"[VEXIS] {f.get('cwe_id', 'CWE-?')}: {f.get('title', 'Vulnerability')} "
            f"(severity: {f.get('severity', '?')}, confidence: {int((f.get('confidence') or 0) * 100)}%)"
        )
        gha_annotation(annotation_level, src_file, f.get("source_line") or 1, msg)

    # Step 7: Check threshold and decide exit code
    blocking_findings = [
        f for f in findings
        if SEVERITY_RANK.get(f.get("severity", "info"), 0) >= THRESHOLD_RANK
    ]

    if blocking_findings:
        gha_log(
            "error",
            f"VEXIS found {len(blocking_findings)} finding(s) at or above threshold '{THRESHOLD}'. "
            "Failing the check. Review findings and remediate before merging."
        )
        return 1

    if findings:
        gha_log(
            "notice",
            f"VEXIS found {len(findings)} finding(s) below threshold '{THRESHOLD}' — check passed."
        )
    else:
        gha_log("notice", "VEXIS: No vulnerabilities found — check passed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
