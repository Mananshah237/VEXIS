"""
Deduplication of correlated findings.

Two-level dedup:
  Level 1 — exact (source:line, sink:line, vuln_class): keep highest confidence.
  Level 2 — (sink_file, sink_line, vuln_class): if 3+ distinct sources all reach the
             same vulnerable sink, collapse to one representative finding and record
             dedup_count so the description can note how many were merged.
"""
from __future__ import annotations
import structlog
from app.correlation.fuser import CorrelatedFinding

log = structlog.get_logger()

# Only collapse at sink level when this many or more sources reach the same sink/vuln_class.
_SINK_COLLAPSE_THRESHOLD = 3


def deduplicate(findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
    """Remove duplicate findings; keep highest confidence per unique source→sink pair,
    then collapse repeated patterns at the same sink location."""

    # Level 1: exact (source:line, sink:line, vuln_class)
    seen1: dict[tuple, CorrelatedFinding] = {}
    for f in findings:
        path = f.confirmed.evaluated.taint_path
        key = (
            f"{path.source.node.file}:{path.source.node.line}",
            f"{path.sink.node.file}:{path.sink.node.line}",
            path.vuln_class,
        )
        if key not in seen1 or f.combined_confidence > seen1[key].combined_confidence:
            seen1[key] = f
    l1 = list(seen1.values())

    # Level 2: (sink_file, sink_line, vuln_class) — collapse high-volume repeated patterns
    sink_groups: dict[tuple, list[CorrelatedFinding]] = {}
    for f in l1:
        path = f.confirmed.evaluated.taint_path
        key = (path.sink.node.file, path.sink.node.line, path.vuln_class)
        sink_groups.setdefault(key, []).append(f)

    result: list[CorrelatedFinding] = []
    for key, group in sink_groups.items():
        if len(group) < _SINK_COLLAPSE_THRESHOLD:
            result.extend(group)
        else:
            best = max(group, key=lambda f: f.combined_confidence)
            best.dedup_count = len(group)
            log.info(
                "dedup.sink_collapsed",
                sink=f"{key[0]}:{key[1]}",
                vuln_class=key[2],
                collapsed=len(group),
            )
            result.append(best)

    return result
