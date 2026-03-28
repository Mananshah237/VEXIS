"""
PDF report builder using WeasyPrint + Jinja2.

build_pdf(scan, findings) -> bytes   — render the full HTML template and return PDF bytes.
build_html(scan, findings) -> str    — render HTML only (no WeasyPrint dep, useful in dev).
"""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"

# ── Jinja2 env ───────────────────────────────────────────────────────────────

def _basename(path: str) -> str:
    return os.path.basename(path) if path else ""


def _truncate(text: str, length: int = 300) -> str:
    if not text:
        return ""
    return text if len(text) <= length else text[:length].rsplit(" ", 1)[0] + "…"


_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)
_jinja_env.filters["basename"] = _basename
_jinja_env.filters["truncate"] = _truncate


# ── Risk scoring ─────────────────────────────────────────────────────────────

_SEV_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _risk_score(findings: list[Any]) -> int:
    """Return a 0–100 risk score."""
    raw = sum(_SEV_WEIGHT.get(f.severity, 0) for f in findings)
    return min(100, raw)


def _risk_color(score: int) -> str:
    if score >= 70:
        return "#ff2d55"
    if score >= 40:
        return "#ff6b35"
    if score >= 20:
        return "#ffd60a"
    return "#34c759"


def _risk_label(score: int) -> str:
    if score >= 70:
        return "Critical Risk"
    if score >= 40:
        return "High Risk"
    if score >= 20:
        return "Medium Risk"
    return "Low Risk"


# ── Template context builder ─────────────────────────────────────────────────

def _build_context(scan: Any, findings: list[Any]) -> dict:  # noqa: C901
    sev_counts: Counter = Counter(f.severity for f in findings)

    # Severity rows for summary table
    severity_rows = []
    for sev in _SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count:
            risk_text = (
                "Immediate action required" if sev == "critical"
                else "Fix before next release" if sev == "high"
                else "Schedule for next sprint" if sev == "medium"
                else "Backlog" if sev == "low"
                else "Informational"
            )
            severity_rows.append((sev, count, risk_text))

    # CWE breakdown rows
    cwe_counter: Counter = Counter()
    cwe_title_map: dict[str, str] = {}
    for f in findings:
        if f.cwe_id:
            cwe_counter[f.cwe_id] += 1
            cwe_title_map[f.cwe_id] = f.title
    cwe_rows = [
        {"cwe_id": cwe, "title": cwe_title_map[cwe], "count": cnt}
        for cwe, cnt in cwe_counter.most_common(20)
    ]

    # OWASP rows
    owasp_counter: Counter = Counter()
    for f in findings:
        if f.owasp_category:
            owasp_counter[f.owasp_category] += 1
    owasp_rows = [
        {"category": cat, "count": cnt}
        for cat, cnt in sorted(owasp_counter.items())
    ]

    # Top critical for exec summary callouts
    top_critical = [f for f in findings if f.severity == "critical"][:3]

    # Executive summary text
    total = len(findings)
    n_crit = sev_counts.get("critical", 0)
    n_high = sev_counts.get("high", 0)
    if total == 0:
        exec_summary = (
            "No vulnerabilities were identified during this scan. "
            "All taint paths were analyzed and no security issues requiring remediation were found."
        )
    else:
        parts = []
        if n_crit:
            parts.append(f"{n_crit} critical")
        if n_high:
            parts.append(f"{n_high} high")
        rest = total - n_crit - n_high
        if rest:
            parts.append(f"{rest} medium/low")
        exec_summary = (
            f"VEXIS identified {total} security finding{'s' if total != 1 else ''} "
            f"({', '.join(parts)}) across the scanned codebase. "
        )
        if n_crit:
            exec_summary += "Critical findings require immediate remediation before deployment. "
        if n_high:
            exec_summary += "High-severity findings should be addressed in the next release cycle."

    # Per-finding display dicts
    finding_dicts = []
    for f in findings:
        poc = f.poc or {}
        taint_path_data = f.taint_path or {}
        taint_steps = taint_path_data.get("path", [])

        remediation_text = ""
        if f.remediation:
            if isinstance(f.remediation, dict):
                remediation_text = (
                    f.remediation.get("description")
                    or f.remediation.get("text")
                    or str(f.remediation)
                )
            else:
                remediation_text = str(f.remediation)
        if not remediation_text:
            remediation_text = (
                "Review and remediate the identified vulnerability following secure coding best practices."
            )

        is_chain = f.vuln_class == "chain"
        chain_steps: list[str] = []
        if is_chain and f.chain_data:
            chain_steps = f.chain_data.get("attack_steps", [])

        finding_dicts.append({
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cwe_id": f.cwe_id or "N/A",
            "owasp_category": f.owasp_category,
            "confidence": f.confidence or 0.0,
            "source_file": f.source_file,
            "source_line": f.source_line,
            "sink_file": f.sink_file,
            "sink_line": f.sink_line,
            "source_code": f.source_code,
            "sink_code": f.sink_code,
            "description": f.description,
            "taint_steps": taint_steps,
            "attack_vector": poc.get("attack_vector") or poc.get("payload"),
            "poc_payload": poc.get("payload") or poc.get("attack_vector"),
            "expected_outcome": poc.get("expected_outcome"),
            "llm_reasoning": f.llm_reasoning,
            "remediation": remediation_text,
            "is_chain": is_chain,
            "chain_steps": chain_steps,
        })

    finding_dicts.sort(
        key=lambda x: _SEV_ORDER.index(x["severity"]) if x["severity"] in _SEV_ORDER else 99
    )

    # Scan metadata
    stats = scan.stats or {}
    scan_date = ""
    if scan.completed_at:
        scan_date = scan.completed_at.strftime("%Y-%m-%d %H:%M UTC")
    elif scan.created_at:
        scan_date = scan.created_at.strftime("%Y-%m-%d %H:%M UTC")

    dur_secs = 0
    if scan.completed_at and scan.created_at:
        dur_secs = int((scan.completed_at - scan.created_at).total_seconds())
    duration_str = f"{dur_secs}s" if dur_secs < 60 else f"{dur_secs // 60}m {dur_secs % 60}s"

    score = _risk_score(findings)

    return {
        # Cover page
        "scan_source": scan.source_ref,
        "scan_date": scan_date,
        "files_parsed": stats.get("files_parsed", 0),
        "duration": duration_str,
        "framework": stats.get("framework"),
        "risk_score": score,
        "risk_color": _risk_color(score),
        "risk_label": _risk_label(score),
        "sev_counts": {
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
        },
        # Executive summary
        "executive_summary": exec_summary,
        "top_critical": [
            {"cwe_id": f.cwe_id or "CWE-?", "title": f.title, "description": f.description}
            for f in top_critical
        ],
        "severity_rows": severity_rows,
        "cwe_rows": cwe_rows,
        # Findings detail
        "findings": finding_dicts,
        # Appendix
        "scan_id": str(scan.id),
        "taint_paths": stats.get("taint_paths", 0),
        "llm_calls": stats.get("llm_calls", 0),
        "skipped_large": stats.get("skipped_large", []),
        "owasp_rows": owasp_rows,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_pdf(scan: Any, findings: list[Any]) -> bytes:
    """Render the full report and return PDF bytes via WeasyPrint."""
    from weasyprint import HTML  # lazy import — not required in dev/test

    ctx = _build_context(scan, findings)
    template = _jinja_env.get_template("report_full.html")
    html_str = template.render(**ctx)
    return HTML(string=html_str, base_url=str(TEMPLATE_DIR)).write_pdf()


def build_html(scan: Any, findings: list[Any]) -> str:
    """Render just the HTML (no WeasyPrint dependency — useful for testing)."""
    ctx = _build_context(scan, findings)
    template = _jinja_env.get_template("report_full.html")
    return template.render(**ctx)
