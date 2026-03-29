#!/usr/bin/env python3
"""
VEXIS CLI — command-line interface for scanning local code.

Local directories are bundled into a raw_code payload (FILE: separator format)
and sent to the API — the server never touches the local filesystem.
"""
import argparse
import asyncio
import sys
from pathlib import Path

# File extensions to include when bundling a local directory
_INCLUDE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx"}
# Max total characters to send (protects against huge repos)
_MAX_PAYLOAD_CHARS = 2_000_000


def _bundle_local(target: str) -> str:
    """Read a local file or directory and return a raw_code string."""
    p = Path(target).resolve()
    files = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted(
            f for f in p.rglob("*")
            if f.is_file()
            and f.suffix in _INCLUDE_EXTS
            and not any(part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv") for part in f.parts)
        )
    else:
        print(f"[VEXIS] Error: '{target}' is not a file or directory.", file=sys.stderr)
        sys.exit(1)

    parts = []
    total = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = f.relative_to(p) if p.is_dir() else f.name
        chunk = f"# === FILE: {rel} ===\n{content}\n"
        total += len(chunk)
        if total > _MAX_PAYLOAD_CHARS:
            print(f"[VEXIS] Warning: payload limit reached — {len(parts)} files included.", file=sys.stderr)
            break
        parts.append(chunk)

    if not parts:
        print("[VEXIS] Error: no supported source files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[VEXIS] Bundling {len(parts)} file(s) as raw_code...")
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(
        prog="vexis",
        description="VEXIS — Vulnerability EXploration & Inference System",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a file, directory, or GitHub URL")
    scan_parser.add_argument("target", help="Local file/directory path or GitHub URL (https://github.com/...)")
    scan_parser.add_argument("--api-url", default="http://localhost:8000", help="VEXIS API URL")
    scan_parser.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low", "info"])

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(run_scan(args))
    else:
        parser.print_help()
        sys.exit(1)


async def run_scan(args):
    import httpx

    if args.target.startswith("http"):
        source_type = "github_url"
        source = args.target
    else:
        source_type = "raw_code"
        source = _bundle_local(args.target)

    print(f"[VEXIS] Scanning: {args.target}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{args.api_url}/api/v1/scan",
            json={"source_type": source_type, "source": source},
        )
        resp.raise_for_status()
        scan = resp.json()
        scan_id = scan["id"]
        print(f"[VEXIS] Scan started: {scan_id}")

        while True:
            await asyncio.sleep(3)
            resp = await client.get(f"{args.api_url}/api/v1/scan/{scan_id}")
            scan = resp.json()
            print(f"[VEXIS] Status: {scan['status']}")

            if scan["status"] in ("complete", "failed"):
                break

        if scan["status"] == "failed":
            print(f"[VEXIS] Scan failed: {scan.get('error_message')}")
            sys.exit(1)

        resp = await client.get(f"{args.api_url}/api/v1/scan/{scan_id}/findings")
        data = resp.json()
        findings = data.get("findings", [])
        print(f"\n[VEXIS] Found {len(findings)} finding(s):\n")
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['title']}")
            print(f"    {f['source_file']}:{f['source_line']} — {f['cwe_id']}")
            print()


if __name__ == "__main__":
    main()
