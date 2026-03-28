"""
Core taint analysis engine.
Worklist-based dataflow propagation over the PDG.
"""
from __future__ import annotations
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


class TaintEngine:
    MAX_PATH_LENGTH = 50
    MAX_ITERATIONS = 10000

    def __init__(self) -> None:
        self._sources = TAINT_SOURCES + JS_TAINT_SOURCES
        self._sinks = TAINT_SINKS + JS_TAINT_SINKS + EXTRA_SINKS
        self._sanitizers = SANITIZERS + JS_SANITIZERS + EXTRA_SANITIZERS

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

    def analyze(self, pdg: PDG) -> list[TaintPath]:
        paths: list[TaintPath] = []
        worklist: list[TaintState] = []

        # Seed worklist with taint sources
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
                if not self._sanitized_for_sink(_effective_sanitizers, sink_pattern.vuln_class):
                    confidence = self._calc_confidence(state, sink_pattern)
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
                    )
                continue  # Don't propagate further past the sink

            # Propagate to successors
            for successor in pdg.get_data_successors(current_node):
                sanitizer = self._match_sanitizer(successor)
                new_taint_type = state.taint_type

                if sanitizer:
                    if sanitizer.is_partial:
                        new_taint_type = TaintType.PARTIALLY_SANITIZED
                        label = f"Partial sanitization: {sanitizer.pattern}"
                    else:
                        # Mark as sanitized but keep propagating — effectiveness
                        # is evaluated at the sink (context-sensitive)
                        new_taint_type = TaintType.PARTIALLY_SANITIZED
                        label = f"Sanitized by: {sanitizer.pattern}"
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

    def _sanitized_for_sink(self, sanitizers: list, vuln_class: str) -> bool:
        """
        Returns True if the taint path has been FULLY sanitized for this specific
        sink type. A sanitizer is only effective if its effective_for list includes
        the sink's vuln_class.

        This enables context-sensitive sanitizer evaluation:
          html.escape() → effective for xss, NOT for sqli
          shlex.quote() → effective for cmdi, NOT for xss
          parameterized query → effective for sqli, NOT for cmdi
        """
        if not sanitizers:
            return False
        # All sanitizers on the path must be effective for this vuln_class
        # AND at least one must be non-partial for this vuln_class
        has_effective = False
        for san in sanitizers:
            if san.effective_for and vuln_class in san.effective_for and not san.is_partial:
                has_effective = True
        return has_effective

    def _calc_confidence(self, state: TaintState, sink: SinkPattern) -> float:
        base = 0.7
        if state.taint_type == TaintType.PARTIALLY_SANITIZED:
            base = 0.5
        if sink.severity == "critical":
            base = min(base + 0.1, 1.0)
        elif sink.severity == "medium":
            base = max(base - 0.1, 0.1)
        if len(state.path) > 10:
            base = max(base - 0.1, 0.1)
        return round(base, 2)
