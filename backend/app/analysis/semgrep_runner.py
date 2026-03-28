"""
Semgrep differential analysis.

Runs Semgrep on the scanned source path and computes which findings
VEXIS found that Semgrep missed (VEXIS-unique), which Semgrep found
that VEXIS missed (Semgrep-unique), and which both found (overlap).

Matching uses: (file, line ± 5, CWE category) for fuzzy deduplication.
Semgrep is run as a subprocess with --config=auto --json --timeout=60.
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import structlog
from dataclasses import dataclass, field
from typing import Optional

log = structlog.get_logger()

# CWE patterns — map semgrep rule IDs to broad vuln classes for comparison
_RULE_TO_VULN_CLASS: dict[str, str] = {
    "sql": "sqli",
    "injection": "sqli",
    "xss": "xss",
    "cross-site": "xss",
    "command": "cmdi",
    "path": "path_traversal",
    "traversal": "path_traversal",
    "ssrf": "ssrf",
    "deserializ": "deserialize",
    "template": "ssti",
    "open-redirect": "open_redirect",
    "csrf": "csrf",
    "auth": "auth_bypass",
}


def _rule_to_vuln_class(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    for keyword, vuln_class in _RULE_TO_VULN_CLASS.items():
        if keyword in rule_lower:
            return vuln_class
    return "unknown"


@dataclass
class SemgrepFinding:
    rule_id: str
    file: str
    line: int
    message: str
    severity: str
    vuln_class: str
    cwe: Optional[str] = None


@dataclass
class DifferentialResult:
    semgrep_available: bool = True
    semgrep_error: Optional[str] = None
    vexis_only: list[dict] = field(default_factory=list)   # VEXIS found, Semgrep missed
    semgrep_only: list[SemgrepFinding] = field(default_factory=list)  # Semgrep found, VEXIS missed
    overlap: list[dict] = field(default_factory=list)       # Both found
    vexis_total: int = 0
    semgrep_total: int = 0


async def run_semgrep(scan_path: str, timeout: float = 60.0) -> list[SemgrepFinding]:
    """Run semgrep --config=auto on scan_path, return parsed findings."""
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "semgrep", "--config=auto", "--json", "--timeout=30",
                "--no-git-ignore",
                scan_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
            ),
            timeout=timeout,
        )
        stdout, stderr = await proc.communicate()
    except asyncio.TimeoutError:
        log.warning("semgrep.timeout", timeout=timeout)
        return []
    except FileNotFoundError:
        log.info("semgrep.not_installed")
        return []
    except Exception as e:
        log.warning("semgrep.failed", error=str(e))
        return []

    if proc.returncode not in (0, 1):  # semgrep exits 1 when findings exist
        log.warning("semgrep.error", stderr=stderr.decode()[:300])
        return []

    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError:
        log.warning("semgrep.json_parse_failed")
        return []

    findings: list[SemgrepFinding] = []
    for result in data.get("results", []):
        rule_id = result.get("check_id", "")
        # Extract CWE from metadata if available
        meta = result.get("extra", {}).get("metadata", {})
        cwe = None
        if "cwe" in meta:
            cwe_val = meta["cwe"]
            if isinstance(cwe_val, list) and cwe_val:
                cwe = cwe_val[0]
            elif isinstance(cwe_val, str):
                cwe = cwe_val

        findings.append(SemgrepFinding(
            rule_id=rule_id,
            file=result.get("path", ""),
            line=result.get("start", {}).get("line", 0),
            message=result.get("extra", {}).get("message", ""),
            severity=result.get("extra", {}).get("severity", "WARNING").lower(),
            vuln_class=_rule_to_vuln_class(rule_id),
            cwe=cwe,
        ))

    log.info("semgrep.done", findings=len(findings))
    return findings


def compute_differential(
    vexis_findings: list,  # list of Finding ORM objects
    semgrep_findings: list[SemgrepFinding],
    line_tolerance: int = 5,
) -> DifferentialResult:
    """
    Match VEXIS findings against Semgrep findings.
    Two findings match if: same file (basename) AND |line_a - line_b| <= tolerance
    AND same vuln_class (or one is 'unknown').
    """
    result = DifferentialResult(
        vexis_total=len(vexis_findings),
        semgrep_total=len(semgrep_findings),
    )

    matched_semgrep_indices: set[int] = set()

    for vf in vexis_findings:
        vf_file = (vf.sink_file or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        vf_line = vf.sink_line or 0
        vf_class = vf.vuln_class or "unknown"

        matched = False
        for i, sf in enumerate(semgrep_findings):
            sf_file = (sf.file or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if sf_file != vf_file:
                continue
            if abs(sf.line - vf_line) > line_tolerance:
                continue
            if sf.vuln_class not in ("unknown", vf_class) and vf_class not in ("unknown",):
                continue
            matched = True
            matched_semgrep_indices.add(i)
            result.overlap.append({
                "vexis": {
                    "file": vf.sink_file,
                    "line": vf_line,
                    "vuln_class": vf_class,
                    "severity": vf.severity,
                    "title": vf.title,
                },
                "semgrep": {
                    "rule_id": sf.rule_id,
                    "file": sf.file,
                    "line": sf.line,
                    "message": sf.message,
                },
            })
            break

        if not matched:
            result.vexis_only.append({
                "file": vf.sink_file,
                "line": vf_line,
                "vuln_class": vf_class,
                "severity": vf.severity,
                "title": vf.title,
                "description": vf.description,
            })

    for i, sf in enumerate(semgrep_findings):
        if i not in matched_semgrep_indices:
            result.semgrep_only.append(sf)

    return result
