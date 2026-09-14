"""
Second-order injection analysis pass.

Detects: HTTP input → parameterized DB write → DB read in another handler → dangerous sink.

Approach: scan all parsed files for:
1. Parameterized INSERT/UPDATE that writes user-controlled data → create db_taint label
2. SELECT/fetchone/fetchall → if any db_taint label was created for same connection → propagate taint

Returns synthetic TaintPath objects that the normal orchestrator pipeline can process.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional
import structlog

log = structlog.get_logger()

# Patterns that indicate a DB write from user-controlled data
# These are INSERT/UPDATE statements using parameterized queries (which suppress normal SQLi detection)
_WRITE_PATTERNS = [
    re.compile(r'execute\s*\(["\']INSERT\s+INTO\s+(\w+)', re.IGNORECASE),
    re.compile(r'execute\s*\(["\']UPDATE\s+(\w+)', re.IGNORECASE),
    re.compile(r'\.create\s*\(', re.IGNORECASE),
    re.compile(r'\.add\s*\(', re.IGNORECASE),
    re.compile(r'session\.add\s*\(', re.IGNORECASE),
]

# Source patterns (same as in trust_boundaries.py) — indicates tainted variable
_HTTP_SOURCE_PATTERNS = [
    "request.args.get",
    "request.form.get",
    "request.json",
    "request.data",
    "req.query",
    "req.body",
    "req.params",
]

# Patterns that indicate a DB read
_READ_PATTERNS = [
    re.compile(r'\.fetchone\(\)', re.IGNORECASE),
    re.compile(r'\.fetchall\(\)', re.IGNORECASE),
    re.compile(r'\.fetchmany\(', re.IGNORECASE),
    re.compile(r'\.first\(\)', re.IGNORECASE),
    re.compile(r'\.all\(\)', re.IGNORECASE),
    re.compile(r'objects\.(get|filter|all)\(', re.IGNORECASE),
    re.compile(r'execute\s*\(["\']SELECT', re.IGNORECASE),
]

# Dangerous sink patterns that consume data read back from the DB.
# NOTE: a constant SQL query (e.g. execute("SELECT 2")) is NOT an injectable
# sink — only interpolated/concatenated queries are — so plain string SELECTs
# are deliberately excluded to avoid flagging constant queries near a read.
_SINK_PATTERNS = [
    ("render_template_string(",  "ssti",           "CWE-1336", "Stored SSTI"),
    ("f\"<",                     "xss",            "CWE-79",   "Stored XSS via f-string"),
    ("f'<",                      "xss",            "CWE-79",   "Stored XSS via f-string"),
    (" + \"<",                   "xss",            "CWE-79",   "Stored XSS via concatenation"),
    ("execute(f\"",              "sqli",           "CWE-89",   "Second-order SQLi via f-string"),
    ("execute(f'",               "sqli",           "CWE-89",   "Second-order SQLi via f-string"),
    ("subprocess.run(",          "cmdi",           "CWE-78",   "Second-order CMDi"),
    ("os.system(",               "cmdi",           "CWE-78",   "Second-order CMDi"),
]

# Table/collection referenced by a DB read, so a read can be matched to the
# write that produced its data instead of relying on line proximity alone.
_READ_TABLE_PATTERNS = [
    re.compile(r'execute\s*\(["\']SELECT\b.*?\bFROM\s+(\w+)', re.IGNORECASE | re.DOTALL),
    re.compile(r'execute\s*\(["\']UPDATE\s+(\w+)', re.IGNORECASE),
    re.compile(r'execute\s*\(["\']DELETE\s+FROM\s+(\w+)', re.IGNORECASE),
]


@dataclass
class SecondOrderFinding:
    """A detected second-order injection vulnerability."""
    write_file: str
    write_line: int
    write_code: str
    read_file: str
    read_line: int
    read_code: str
    sink_file: str
    sink_line: int
    sink_code: str
    vuln_class: str
    cwe_id: str
    description: str
    db_table: Optional[str] = None


def _has_http_source(line: str) -> bool:
    return any(pat in line for pat in _HTTP_SOURCE_PATTERNS)


def _find_writes(file_path: str, source: str) -> list[tuple[int, str, Optional[str]]]:
    """Find lines where tainted data is written to DB. Returns [(line_no, code, table)].

    Checks if an HTTP source appears within 8 lines BEFORE the write statement
    to handle the common pattern:
        username = request.form.get(...)   # HTTP source (line N)
        db.execute("INSERT ...", (username,))  # write (line N+2)
    """
    writes = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pat in _WRITE_PATTERNS:
            m = pat.search(line)
            if m:
                # Check if an HTTP source appears in the preceding 8 lines
                window_start = max(0, i - 9)  # 0-indexed
                window = lines[window_start:i]  # lines before this write
                if any(_has_http_source(w) for w in window):
                    table = m.group(1) if m.lastindex else None
                    writes.append((i, line.strip(), table))
                break
    return writes


def _read_table(line: str) -> Optional[str]:
    """Table/collection a read line pulls from, if it can be determined."""
    for pat in _READ_TABLE_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1).lower()
    return None


def _find_reads(source: str) -> list[tuple[int, str, Optional[str]]]:
    """Find lines where data is read from DB. Returns [(line_no, code, table)]."""
    reads = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pat in _READ_PATTERNS:
            if pat.search(line):
                reads.append((i, line.strip(), _read_table(line)))
                break
    return reads


def _find_sinks_after_read(source: str, read_line: int) -> list[tuple[int, str, str, str, str]]:
    """Find dangerous sinks in the ~20 lines after a DB read. Returns [(line_no, code, vuln_class, cwe, desc)]."""
    lines = source.splitlines()
    sinks = []
    # Look in a window of 20 lines after the read
    start = read_line  # already 1-indexed
    end = min(len(lines), start + 20)
    for i in range(start, end):
        line = lines[i]  # 0-indexed
        for pattern, vuln_class, cwe, desc in _SINK_PATTERNS:
            if pattern in line:
                sinks.append((i + 1, line.strip(), vuln_class, cwe, desc))
                break
    return sinks


def analyze_second_order(parsed_files: list) -> list[SecondOrderFinding]:
    """
    Analyze all parsed files for second-order injection patterns.

    Algorithm:
    1. Find all DB writes from HTTP sources across all files
    2. For each file with DB reads, check if there's any DB write context
    3. Find dangerous sinks near DB reads
    4. Report findings
    """
    findings = []

    # Collect all writes across all files. A write is only usable for
    # correlation if we can identify the table it targets.
    all_writes: list[tuple[str, int, str, Optional[str]]] = []
    for pf in parsed_files:
        writes = _find_writes(pf.path, pf.source)
        for line_no, code, table in writes:
            all_writes.append((pf.path, line_no, code, table))

    # Index writes by the (lower-cased) table they populate. Writes whose table
    # cannot be determined (e.g. bare ORM .add()) are not used for correlation,
    # because there is no evidence the read pulls back the same data.
    writes_by_table: dict[str, tuple[str, int, str, str]] = {}
    for wf, wl, wc, table in all_writes:
        if table:
            writes_by_table.setdefault(table.lower(), (wf, wl, wc, table))

    if not writes_by_table:
        return []

    log.debug("second_order.writes_found", count=len(all_writes), tables=list(writes_by_table))

    # For each file, look for DB reads followed by sinks. Report only when the
    # read pulls from a table a tainted write populated — proven table identity,
    # not mere line proximity.
    for pf in parsed_files:
        reads = _find_reads(pf.source)
        for read_line, read_code, read_table in reads:
            if not read_table or read_table not in writes_by_table:
                continue
            write_file, write_line, write_code, table = writes_by_table[read_table]
            sinks = _find_sinks_after_read(pf.source, read_line)
            for sink_line, sink_code, vuln_class, cwe, desc in sinks:
                finding = SecondOrderFinding(
                    write_file=write_file,
                    write_line=write_line,
                    write_code=write_code,
                    read_file=pf.path,
                    read_line=read_line,
                    read_code=read_code,
                    sink_file=pf.path,
                    sink_line=sink_line,
                    sink_code=sink_code,
                    vuln_class=vuln_class,
                    cwe_id=cwe,
                    description=(
                        f"{desc} (second-order: data read from '{table}' was stored "
                        f"from user input in {write_file}:{write_line})"
                    ),
                    db_table=table,
                )
                findings.append(finding)

    log.info("second_order.analysis_complete", findings=len(findings))
    return findings
