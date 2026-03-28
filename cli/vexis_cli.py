#!/usr/bin/env python3
"""
VEXIS CLI — command-line interface for scanning local code.
"""
import argparse
import asyncio
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="vexis",
        description="VEXIS — Vulnerability EXploration & Inference System",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("target", help="File path, directory, or GitHub URL")
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

    source_type = "github_url" if args.target.startswith("http") else "file_upload"
    print(f"[VEXIS] Scanning: {args.target}")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{args.api_url}/api/v1/scan",
            json={"source_type": source_type, "source": args.target},
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
