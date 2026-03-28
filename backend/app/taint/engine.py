"""
Core taint analysis engine.
Worklist-based dataflow propagation over the PDG.

CCSM: sanitizer strength is expressed as constraint_power (0.0-1.0).
danger_score starts at 1.0 and is multiplied by (1 - constraint_power) for
each sanitizer encountered. Paths whose effective danger (for the specific
sink type) drops below DANGER_THRESHOLD are suppressed; the score is used
directly as taint_confidence in findings.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional
import re
import structlog

if TYPE_CHECKING:
    from app.ingestion.frameworks.profiles import FrameworkProfile

from app.ingestion.pdg_builder import PDG, PDGNode, EdgeType, NodeType
from app.ingestion.trust_boundaries import (
    TAINT_SOURCES, TAINT_SINKS, SANITIZERS,
    JS_TAINT_SOURCES, JS_TAINT_SINKS, JS_SANITIZERS,
    EXTRA_SINKS, EXTRA_SANITIZERS,
    SourcePattern, SinkPattern, SanitizerPattern,
)

log = structlog.get_logger()


class TaintType(str, Enum):
    TAINTED = "tainted"
    PARTIALLY_SANITIZED = "partially_sanitized"
    CLEARED = "cleared"


@dataclass
class TaintNode:
    node: PDGNode
    taint_type: TaintType
    label: str  # human readable description of what's happening


@dataclass
class TaintSource:
    node: PDGNode
    pattern: SourcePattern


@dataclass
class TaintSink:
    node: PDGNode
    pattern: SinkPattern


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    path: list[TaintNode]
    sanitizers: list[SanitizerPattern] = field(default_factory=list)
    partial_sanitizers: list[SanitizerPattern] = field(default_factory=list)
    confidence: float = 0.5
    vuln_class: str = ""


@dataclass
class TaintState:
    variable: str
    taint_label: str
    taint_type: TaintType
    source: TaintSource
    path: list[TaintNode]
    path_sanitizers: list[SanitizerPattern] = field(default_factory=list)
    danger_score: float = 1.0  # starts at 1.0, reduced multiplicatively by sanitizers


class TaintEngine:
    MAX_PATH_LENGTH = 50
    MAX_ITERATIONS = 10000

    def __init__(self) -> None:
        self._sources = TAINT_SOURCES + JS_TAINT_SOURCES
        self._sinks = TAINT_SINKS + JS_TAINT_SINKS + EXTRA_SINKS
        self._sanitizers = SANITIZERS + JS_SANITIZERS + EXTRA_SANITIZERS
        # Early-termination threshold: paths with danger below this are not reported
        self._danger_threshold = float(os.environ.get("VEXIS_DANGER_THRESHOLD", "0.15"))

    def apply_framework_profile(self, profile: "FrameworkProfile") -> None:
        """Merge framework-specific patterns into the running engine."""
        self._sources = self._sources + profile.extra_sources
        self._sinks = self._sinks + profile.extra_sinks
        self._sanitizers = self._sanitizers + profile.extra_sanitizers
        log.debug("framework_profile.applied", framework=profile.name,
                  extra_sources=len(profile.extra_sources),
                  extra_sinks=len(profile.extra_sinks))

    def analyze_project(
        self,
        pdgs: dict[str, PDG],
        call_graph,
    ) -> list[TaintPath]:
        """
        Cross-file analysis: merge all per-file PDGs, inject cross-file edges,
        then run the standard worklist taint analysis on the unified graph.
        """
        from app.taint.cross_file import CrossFileLinker
        unified = CrossFileLinker().link(pdgs, call_graph)
        return self.analyze(unified)

    def get_last_folded_pdg(self) -> "PDG | None":
        """Return the folded PDG from the most recent analyze() call, for unfolding paths."""
        return getattr(self, "_last_folded_pdg", None)

    def analyze(self, pdg: PDG) -> list[TaintPath]:
        # Graph folding: collapse passthrough chains before worklist traversal
        from app.ingestion.graph_folder import fold_pdg
        pdg = fold_pdg(pdg)
        self._last_folded_pdg = pdg  # stored for path unfolding after analysis

        paths: list[TaintPath] = []
        worklist: list[TaintState] = []

        # Seed worklist with taint sources (danger_score starts at 1.0)
        for node in pdg.nodes():
            source_pattern = self._match_source(node)
            if source_pattern:
                source = TaintSource(node=node, pattern=source_pattern)
                state = TaintState(
                    variable=node.code,
                    taint_label=f"src:{node.line}",
                    taint_type=TaintType.TAINTED,
                    source=source,
                    path=[TaintNode(node=node, taint_type=TaintType.TAINTED, label=f"User input via {source_pattern.source_type}")],
                    danger_score=1.0,
                )
                worklist.append(state)
                log.debug("taint.source", file=node.file, line=node.line, pattern=source_pattern.pattern)

        visited: set[tuple[str, str, str]] = set()
        iterations = 0

        while worklist and iterations < self.MAX_ITERATIONS:
            iterations += 1
            state = worklist.pop(0)

            if len(state.path) > self.MAX_PATH_LENGTH:
                continue

            current_node = state.path[-1].node
            visit_key = (state.taint_label, current_node.id, state.taint_type)
            if visit_key in visited:
                continue
            visited.add(visit_key)

            # Check if current node is a sink
            sink_pattern = self._match_sink(current_node)
            if sink_pattern and state.taint_type != TaintType.CLEARED:
                # Also check if the sink node ITSELF contains an effective sanitizer —
                # this handles coarse-grained JS PDG nodes where a single node may
                # contain both a sink call and a sanitizer (e.g., parameterized query).
                _node_sanitizer = self._match_sanitizer(current_node)
                _effective_sanitizers = list(state.path_sanitizers)
                if _node_sanitizer:
                    _effective_sanitizers.append(_node_sanitizer)
                # Compute effective danger for this specific sink type (CCSM)
                effective_danger = self._calc_effective_danger(_effective_sanitizers, sink_pattern.vuln_class)
                if effective_danger >= self._danger_threshold:
                    confidence = self._calc_confidence(state, sink_pattern, effective_danger)
                    path = TaintPath(
                        source=state.source,
                        sink=TaintSink(node=current_node, pattern=sink_pattern),
                        path=list(state.path),
                        sanitizers=state.path_sanitizers,
                        confidence=confidence,
                        vuln_class=sink_pattern.vuln_class,
                    )
                    paths.append(path)
                    log.debug(
                        "taint.path_found",
                        vuln_class=sink_pattern.vuln_class,
                        source_line=state.source.node.line,
                        sink_line=current_node.line,
                        confidence=confidence,
                        effective_danger=round(effective_danger, 3),
                    )
                continue  # Don't propagate further past the sink

            # Propagate to successors
            for successor in pdg.get_data_successors(current_node):
                sanitizer = self._match_sanitizer(successor)
                new_taint_type = state.taint_type
                new_danger = state.danger_score

                if sanitizer:
                    # Apply constraint to propagation-time danger score
                    new_danger = state.danger_score * (1.0 - sanitizer.constraint_power)
                    if sanitizer.is_partial:
                        label = f"Partial sanitization: {sanitizer.pattern}"
                    else:
                        label = f"Sanitized by: {sanitizer.pattern}"
                    new_taint_type = TaintType.PARTIALLY_SANITIZED
                    log.debug(
                        "taint.propagation",
                        danger_score=round(new_danger, 3),
                        sanitizer=sanitizer.pattern,
                        constraint=sanitizer.constraint_power,
                    )
                    # Early termination: if even the worst-case path danger drops below
                    # threshold, stop propagating — no sink of any type would fire
                    if new_danger < self._danger_threshold:
                        log.debug("taint.early_termination",
                                  danger=round(new_danger, 3),
                                  threshold=self._danger_threshold)
                        continue
                else:
                    label = f"Data flows to: {successor.label}"

                new_path = state.path + [
                    TaintNode(node=successor, taint_type=new_taint_type, label=label)
                ]
                new_sanitizers = list(state.path_sanitizers)
                if sanitizer:
                    new_sanitizers.append(sanitizer)
                new_state = TaintState(
                    variable=successor.code[:50],
                    taint_label=state.taint_label,
                    taint_type=new_taint_type,
                    source=state.source,
                    path=new_path,
                    path_sanitizers=new_sanitizers,
                    danger_score=new_danger,
                )
                worklist.append(new_state)

        log.info("taint.analysis_complete", paths_found=len(paths), iterations=iterations)
        return self._dedup_paths(paths)

    def _dedup_paths(self, paths: list[TaintPath]) -> list[TaintPath]:
        """Deduplicate taint paths by (source_file:line, sink_file:line, vuln_class).
        Keeps the highest-confidence path for each unique source→sink pair."""
        seen: dict[tuple, TaintPath] = {}
        for p in paths:
            key = (
                p.source.node.file, p.source.node.line,
                p.sink.node.file, p.sink.node.line,
                p.vuln_class,
            )
            if key not in seen or p.confidence > seen[key].confidence:
                seen[key] = p
        return list(seen.values())

    # Node types where source/sink pattern matching is meaningful
    _MATCHABLE_NODE_TYPES = {
        NodeType.CALL,
        NodeType.ASSIGNMENT,
        NodeType.STATEMENT,
        NodeType.EXPRESSION,
        NodeType.RETURN,
    }

    @staticmethod
    def _pattern_matches(pattern: str, code: str) -> bool:
        """Match pattern against code using word boundaries for patterns that start
        with a letter (avoids e.g. `input(` matching inside `get_user_input()`)."""
        if not pattern:
            return False
        if pattern[0].isalpha() or pattern[0] == '_':
            return bool(re.search(r'\b' + re.escape(pattern), code))
        return pattern in code

    def _match_source(self, node: PDGNode) -> Optional[SourcePattern]:
        if node.node_type not in self._MATCHABLE_NODE_TYPES:
            return None
        code = node.code
        for pattern in self._sources:
            if self._pattern_matches(pattern.pattern, code):
                return pattern
        return None

    def _match_sink(self, node: PDGNode) -> Optional[SinkPattern]:
        if node.node_type not in self._MATCHABLE_NODE_TYPES:
            return None
        code = node.code
        for pattern in self._sinks:
            if self._pattern_matches(pattern.pattern, code):
                return pattern
        return None

    def _match_sanitizer(self, node: PDGNode) -> Optional[SanitizerPattern]:
        code = node.code
        for pattern in self._sanitizers:
            if pattern.pattern and pattern.pattern in code:
                return pattern
        return None

    def _calc_effective_danger(self, sanitizers: list, vuln_class: str) -> float:
        """
        Compute the effective danger score for a specific sink type (CCSM).
        Multiplies (1 - constraint_power) for each sanitizer effective for vuln_class.
        Returns 1.0 if no sanitizers present (fully dangerous).

        Context-sensitive: html.escape() effective for xss, NOT sqli.
        """
        danger = 1.0
        for san in sanitizers:
            if san.effective_for and vuln_class in san.effective_for:
                danger *= (1.0 - san.constraint_power)
        return danger

    def _sanitized_for_sink(self, sanitizers: list, vuln_class: str) -> bool:
        """Backward-compat wrapper: a path is sanitized if effective danger is below threshold."""
        return self._calc_effective_danger(sanitizers, vuln_class) < self._danger_threshold

    def _calc_confidence(self, state: TaintState, sink: SinkPattern, effective_danger: float = 0.7) -> float:
        """Map effective danger score to finding confidence.

        effective_danger=1.0 (no sanitization) → high confidence
        effective_danger=0.30 (moderate sanitization) → lower confidence
        """
        base = effective_danger
        if sink.severity == "critical":
            base = min(base + 0.05, 1.0)
        elif sink.severity == "medium":
            base = max(base - 0.05, 0.1)
        if len(state.path) > 10:
            base = max(base - 0.1, 0.1)
        return round(base, 2)
