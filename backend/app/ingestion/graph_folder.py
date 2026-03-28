"""
Graph Folding: collapse passthrough-only chains in PDGs to reduce traversal cost.

A passthrough node has exactly 1 DATA_DEP predecessor and 1 DATA_DEP successor
and is not an anchor (source, sink, sanitizer, branch condition, call site,
function definition, or return statement).

Collapsing A → B → C → D (where B and C are passthroughs) into A → D:
  - The new A→D edge stores folded_nodes=[B_data, C_data]
  - After taint analysis, call unfold_path() to reconstruct the full node list

The folded PDG is API-transparent: the taint engine sees the same PDG class
and finds the same sources/sinks. The frontend always receives full paths.
"""
from __future__ import annotations
from typing import Any

import structlog

from app.ingestion.pdg_builder import PDG, PDGNode, NodeType, EdgeType
from app.ingestion.trust_boundaries import (
    TAINT_SOURCES, TAINT_SINKS, SANITIZERS,
    JS_TAINT_SOURCES, JS_TAINT_SINKS, JS_SANITIZERS,
    EXTRA_SINKS, EXTRA_SANITIZERS,
)

log = structlog.get_logger()

# Node types that are always anchors — cannot be folded away
_ANCHOR_NODE_TYPES = {
    NodeType.CALL,
    NodeType.CONDITION,
    NodeType.FUNCTION_DEF,
    NodeType.RETURN,
    NodeType.PARAMETER,
}


def _build_pattern_set() -> frozenset[str]:
    """Build a fast lookup set of all source/sink/sanitizer pattern strings."""
    patterns: set[str] = set()
    all_lists = [
        TAINT_SOURCES, JS_TAINT_SOURCES,
        TAINT_SINKS, JS_TAINT_SINKS, EXTRA_SINKS,
        SANITIZERS, JS_SANITIZERS, EXTRA_SANITIZERS,
    ]
    for lst in all_lists:
        for item in lst:
            if item.pattern:
                patterns.add(item.pattern)
    return frozenset(patterns)


_PATTERN_SET = _build_pattern_set()


def _is_passthrough(node: PDGNode, graph: Any, pattern_set: frozenset[str]) -> bool:
    """Return True if this node can be safely folded away."""
    import networkx as nx  # nx already imported by PDG

    if node.node_type in _ANCHOR_NODE_TYPES:
        return False

    # Must have exactly 1 DATA_DEP predecessor and 1 DATA_DEP successor
    data_preds = [
        n for n in graph.predecessors(node.id)
        if graph.edges[n, node.id].get("edge_type") == EdgeType.DATA_DEP
    ]
    data_succs = [
        n for n in graph.successors(node.id)
        if graph.edges[node.id, n].get("edge_type") == EdgeType.DATA_DEP
    ]
    if len(data_preds) != 1 or len(data_succs) != 1:
        return False

    # Must not be a source, sink, or sanitizer
    code = node.code
    if any(p in code for p in pattern_set):
        return False

    return True


def fold_pdg(pdg: PDG) -> PDG:
    """Return a new PDG with passthrough chains collapsed.

    The returned PDG has the same interface as the original.  Collapsed edges
    carry ``folded_nodes`` metadata listing the intermediate PDGNode dicts so
    that taint paths can be unfolded before serialisation.
    """
    import networkx as nx

    g = pdg.graph
    original_count = g.number_of_nodes()

    # Build set of passthrough node IDs
    passthrough_ids: set[str] = set()
    for node_id in list(g.nodes):
        node_data: PDGNode = g.nodes[node_id]["data"]
        if _is_passthrough(node_data, g, _PATTERN_SET):
            passthrough_ids.add(node_id)

    if not passthrough_ids:
        log.debug("graph_folder.no_passthroughs", file=pdg.file, nodes=original_count)
        return pdg  # nothing to fold

    # Build the new graph preserving all non-passthrough nodes and non-data edges
    new_g = nx.DiGraph()

    # Add all anchor nodes
    for node_id in g.nodes:
        if node_id not in passthrough_ids:
            new_g.add_node(node_id, **g.nodes[node_id])

    # Add all non-DATA_DEP edges between non-passthrough nodes
    for u, v, data in g.edges(data=True):
        if data.get("edge_type") != EdgeType.DATA_DEP:
            if u not in passthrough_ids and v not in passthrough_ids:
                new_g.add_edge(u, v, **data)

    # For each DATA_DEP edge from a non-passthrough to a (possibly) passthrough chain,
    # trace the chain to the terminal non-passthrough node and create a single edge.
    for node_id in g.nodes:
        if node_id in passthrough_ids:
            continue
        for succ_id in list(g.successors(node_id)):
            edge_data = g.edges[node_id, succ_id]
            if edge_data.get("edge_type") != EdgeType.DATA_DEP:
                continue
            if succ_id not in passthrough_ids:
                # Direct edge to non-passthrough — keep as-is
                if not new_g.has_edge(node_id, succ_id):
                    new_g.add_edge(node_id, succ_id, **edge_data)
                continue

            # Walk the passthrough chain
            folded: list[dict] = []
            current = succ_id
            while current in passthrough_ids:
                n_data: PDGNode = g.nodes[current]["data"]
                folded.append({
                    "id": n_data.id,
                    "file": n_data.file,
                    "line": n_data.line,
                    "code": n_data.code,
                    "node_type": n_data.node_type,
                    "label": n_data.label,
                })
                # Move to next DATA_DEP successor in the chain
                next_succs = [
                    s for s in g.successors(current)
                    if g.edges[current, s].get("edge_type") == EdgeType.DATA_DEP
                ]
                if len(next_succs) != 1:
                    break
                current = next_succs[0]

            # 'current' is now the terminal node (non-passthrough or end of chain)
            if current not in passthrough_ids and current != node_id:
                if not new_g.has_edge(node_id, current):
                    new_g.add_edge(
                        node_id, current,
                        edge_type=EdgeType.DATA_DEP,
                        folded_nodes=folded,
                    )

    folded_count = new_g.number_of_nodes()
    ratio = folded_count / original_count if original_count else 1.0
    log.info(
        "graph_folder.complete",
        file=pdg.file,
        original_nodes=original_count,
        folded_nodes=folded_count,
        ratio=round(ratio, 2),
    )

    return PDG(graph=new_g, file=pdg.file)


def unfold_path(path_nodes: list[Any], folded_pdg: PDG) -> list[Any]:
    """Expand folded intermediate nodes back into a taint path node list.

    ``path_nodes`` is a list of TaintNode (or any object with ``.node.id``).
    For each consecutive pair (A, B) in the path, if the folded PDG has a
    ``folded_nodes`` attribute on edge A→B, the intermediate nodes are
    inserted as plain TaintNode-like dicts before B.
    """
    from app.taint.engine import TaintNode, TaintType

    if len(path_nodes) < 2:
        return path_nodes

    g = folded_pdg.graph
    expanded: list[Any] = [path_nodes[0]]

    for i in range(1, len(path_nodes)):
        prev = path_nodes[i - 1]
        curr = path_nodes[i]
        prev_id = prev.node.id
        curr_id = curr.node.id

        if g.has_edge(prev_id, curr_id):
            folded = g.edges[prev_id, curr_id].get("folded_nodes", [])
            for fn in folded:
                # Reconstruct a minimal PDGNode-compatible object
                from app.ingestion.pdg_builder import PDGNode, NodeType
                synthetic_node = PDGNode(
                    id=fn["id"],
                    node_type=fn.get("node_type", NodeType.STATEMENT),
                    label=fn.get("label", ""),
                    file=fn["file"],
                    line=fn["line"],
                    col=0,
                    code=fn["code"],
                )
                expanded.append(TaintNode(
                    node=synthetic_node,
                    taint_type=prev.taint_type,
                    label=f"(folded) {fn.get('label', fn['code'][:60])}",
                ))

        expanded.append(curr)

    return expanded
