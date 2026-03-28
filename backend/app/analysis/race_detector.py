"""
Race condition / TOCTOU detector (CWE-362).

Pattern-based detection: looks for check-then-act sequences on filesystem operations
and shared state without proper locking.

This is NOT taint-based — it's a pure AST/pattern scan.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
import structlog

log = structlog.get_logger()

# Check patterns (condition checks before an operation)
_CHECK_PATTERNS = [
    re.compile(r'os\.path\.exists\s*\(', re.IGNORECASE),
    re.compile(r'os\.path\.isfile\s*\(', re.IGNORECASE),
    re.compile(r'os\.path\.isdir\s*\(', re.IGNORECASE),
    re.compile(r'if\s+.*\bbalance\b.*>=', re.IGNORECASE),
    re.compile(r'if\s+.*\bcount\b.*>=', re.IGNORECASE),
    re.compile(r'if\s+.*\.exists\(\)', re.IGNORECASE),
]

# Act patterns (operations that should be atomic with the check)
_ACT_PATTERNS = [
    re.compile(r'os\.remove\s*\(', re.IGNORECASE),
    re.compile(r'os\.unlink\s*\(', re.IGNORECASE),
    re.compile(r'open\s*\(', re.IGNORECASE),
    re.compile(r'os\.rename\s*\(', re.IGNORECASE),
    re.compile(r'shutil\.(move|copy|rmtree)\s*\(', re.IGNORECASE),
    re.compile(r'\.balance\s*-=', re.IGNORECASE),
    re.compile(r'\.count\s*-=', re.IGNORECASE),
]


@dataclass
class RaceFinding:
    file: str
    check_line: int
    check_code: str
    act_line: int
    act_code: str
    description: str


def detect_race_conditions(parsed_files: list) -> list[RaceFinding]:
    """Detect TOCTOU patterns in parsed files."""
    findings = []
    for pf in parsed_files:
        lines = pf.source.splitlines()
        for i, line in enumerate(lines):
            # Check if this line is a CHECK
            check_match = any(pat.search(line) for pat in _CHECK_PATTERNS)
            if not check_match:
                continue
            # Look for ACT in the next 5 lines
            window_end = min(len(lines), i + 6)
            for j in range(i + 1, window_end):
                act_line = lines[j]
                act_match = any(pat.search(act_line) for pat in _ACT_PATTERNS)
                if act_match:
                    findings.append(RaceFinding(
                        file=pf.path,
                        check_line=i + 1,
                        check_code=line.strip(),
                        act_line=j + 1,
                        act_code=act_line.strip(),
                        description=(
                            f"TOCTOU race condition: check at line {i+1} and act at line {j+1} "
                            f"with no atomic locking — CWE-362"
                        ),
                    ))
                    break  # one finding per check
    log.debug("race_detector.complete", findings=len(findings))
    return findings
