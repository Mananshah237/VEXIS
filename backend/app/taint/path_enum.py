"""
Path enumeration — deduplication and ranking of taint paths.
"""
from __future__ import annotations
from app.taint.engine import TaintPath


def deduplicate_paths(paths: list[TaintPath]) -> list[TaintPath]:
    """Remove duplicate source-sink pairs, keeping highest confidence."""
    seen: dict[tuple[str, str, str], TaintPath] = {}
    for path in paths:
        key = (
            f"{path.source.node.file}:{path.source.node.line}",
            f"{path.sink.node.file}:{path.sink.node.line}",
            path.vuln_class,
        )
        if key not in seen or path.confidence > seen[key].confidence:
            seen[key] = path
    return list(seen.values())


def rank_paths(paths: list[TaintPath]) -> list[TaintPath]:
    """Sort paths by estimated severity (confidence * sink severity weight)."""
    severity_weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
    return sorted(
        paths,
        key=lambda p: p.confidence * severity_weight.get(p.sink.pattern.severity, 0.5),
        reverse=True,
    )
