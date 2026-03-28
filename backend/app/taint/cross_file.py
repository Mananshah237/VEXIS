"""
Cross-file taint linker.
Merges per-file PDGs into a single project-wide PDG and injects
interprocedural DATA_DEP edges for three cross-file flow patterns:

  1. Shared-state stores/loads  — request.state.X, session["KEY"]
  2. Function arg -> parameter  — tainted arg in caller -> param uses in callee
  3. Return values              — tainted return in callee -> assignment at call site

Third-party / vendored files are excluded at link time: if _resolve_callee
resolves to a file that matches any exclusion pattern, the cross-file edge is
not added.  This prevents taint from flowing into (and being reported inside)
jquery.min.js, node_modules, vendor/, etc.
"""
from __future__ import annotations
import re
from typing import Optional

import networkx as nx
import structlog

from app.ingestion.pdg_builder import PDG, PDGNode, EdgeType, NodeType
from app.ingestion.call_graph import ProjectCallGraph

log = structlog.get_logger()


def _is_third_party_file(file_path: str) -> bool:
    """Return True if the file path looks like a vendored / generated file."""
    from app.config import settings
    norm = file_path.replace("\\", "/").lower()
    for pat in settings.excluded_path_patterns:
        if pat.lower() in norm:
            return True
    name = norm.rsplit("/", 1)[-1]
    for pat in settings.excluded_filename_patterns:
        if name.endswith(pat.lower()):
            return True
    return False

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Detects "LHS = RHS" where LHS has a dot (attribute store) or bracket (dict store)
_ATTR_STORE_RE = re.compile(r'^((?:\w+\.)+\w+)\s*(?<![=!<>])=(?!=)')
_DICT_STORE_RE = re.compile(r'^(\w+)\[(["\'])([^"\']+)\2\]\s*(?<![=!<>])=(?!=)')

# Reads patterns (match anywhere in code)
_ATTR_READ_RE = re.compile(r'\b((?:\w+\.){1,}\w+)\b')
_DICT_READ_RE = re.compile(r'\b(\w+)\[(["\'])([^"\']+)\2\]')

# Simple function call: FUNCNAME(args)
_CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(([^)]*)\)')

_KEYWORDS = frozenset({
    'True', 'False', 'None', 'and', 'or', 'not', 'in', 'is', 'if', 'else',
    'for', 'while', 'return', 'import', 'from', 'def', 'class', 'try',
    'except', 'finally', 'with', 'as', 'pass', 'break', 'continue', 'lambda',
    'yield', 'assert', 'del', 'global', 'nonlocal', 'raise', 'print', 'len',
    'range', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'bool',
    'type', 'isinstance', 'hasattr', 'getattr', 'setattr', 'open', 'super',
})


def _last_ident(expr: str) -> str:
    tokens = re.findall(r'\b([A-Za-z_]\w*)\b', expr)
    for tok in reversed(tokens):
        if tok not in _KEYWORDS:
            return tok
    return ""


class CrossFileLinker:
    """
    Builds a project-wide PDG by merging per-file PDGs and adding
    cross-file DATA_DEP edges for shared state, function args, and return values.
    """

    def link(
        self,
        pdgs: dict[str, PDG],
        call_graph: ProjectCallGraph,
    ) -> PDG:
        if not pdgs:
            raise ValueError("No PDGs to link")

        # Drop third-party PDGs before merging — they should never be in the
        # project graph since the file filter already excluded them at parse time,
        # but this is a belt-and-suspenders guard for edge cases.
        filtered = {f: p for f, p in pdgs.items() if not _is_third_party_file(f)}
        if len(filtered) < len(pdgs):
            log.debug(
                "cross_file.dropped_third_party",
                dropped=len(pdgs) - len(filtered),
            )
        pdgs = filtered
        if not pdgs:
            raise ValueError("No application PDGs remaining after third-party filter")

        merged = self._merge(pdgs)
        all_nodes: list[PDGNode] = [merged.nodes[n]["data"] for n in merged.nodes]

        s = self._add_shared_state_edges(merged, all_nodes)
        c = self._add_call_edges(merged, all_nodes, call_graph)
        r = self._add_return_edges(merged, all_nodes, call_graph)

        log.info("cross_file.linked",
                 files=len(pdgs), nodes=merged.number_of_nodes(),
                 state_edges=s, call_edges=c, return_edges=r)
        return PDG(graph=merged, file="<project>")

    # ------------------------------------------------------------------
    # 1. Merge per-file PDGs with globally unique node IDs
    # ------------------------------------------------------------------

    def _merge(self, pdgs: dict[str, PDG]) -> nx.DiGraph:
        merged = nx.DiGraph()
        for file_idx, (file_path, pdg) in enumerate(pdgs.items()):
            prefix = f"f{file_idx}_"
            for node_id in pdg.graph.nodes:
                new_id = f"{prefix}{node_id}"
                old: PDGNode = pdg.graph.nodes[node_id]["data"]
                new_node = PDGNode(
                    id=new_id,
                    node_type=old.node_type,
                    label=old.label,
                    file=old.file,
                    line=old.line,
                    col=old.col,
                    code=old.code,
                    ast_node=old.ast_node,
                    variables_defined=list(old.variables_defined),
                    variables_used=list(old.variables_used),
                    function_calls=list(old.function_calls),
                )
                merged.add_node(new_id, data=new_node)
            for src, dst, edata in pdg.graph.edges(data=True):
                merged.add_edge(f"{prefix}{src}", f"{prefix}{dst}", **edata)
        return merged

    # ------------------------------------------------------------------
    # 2. Shared-state edges
    # ------------------------------------------------------------------

    def _add_shared_state_edges(
        self, graph: nx.DiGraph, all_nodes: list[PDGNode]
    ) -> int:
        stores: dict[str, list[PDGNode]] = {}
        loads: dict[str, list[PDGNode]] = {}

        for node in all_nodes:
            code = node.code.strip()
            sk = self._detect_store(code)
            if sk:
                stores.setdefault(sk, []).append(node)
            else:
                for k in self._detect_reads(code):
                    loads.setdefault(k, []).append(node)

        added = 0
        for key, wnodes in stores.items():
            rnodes = loads.get(key, [])
            for wn in wnodes:
                for rn in rnodes:
                    if wn.id != rn.id and wn.file != rn.file:
                        if not graph.has_edge(wn.id, rn.id):
                            graph.add_edge(wn.id, rn.id,
                                           edge_type=EdgeType.DATA_DEP,
                                           var=f"<shared:{key}>")
                            added += 1
        return added

    def _detect_store(self, code: str) -> Optional[str]:
        m = _DICT_STORE_RE.match(code)
        if m:
            return f'{m.group(1)}["{m.group(3)}"]'
        m2 = _ATTR_STORE_RE.match(code)
        if m2:
            lhs = m2.group(1)
            if "." in lhs:
                return lhs
        return None

    def _detect_reads(self, code: str) -> list[str]:
        # For assignments, only scan the RHS for reads
        eq = code.find("=")
        if eq > 0 and code[eq - 1] not in "!<>" and (eq + 1 >= len(code) or code[eq + 1] != "="):
            # Check if LHS has a dot (attribute assignment) — if so this is a store, skip
            lhs = code[:eq].strip()
            if "." in lhs or "[" in lhs:
                return []
            scan = code[eq + 1:]
        else:
            scan = code

        keys: list[str] = []
        for m in _ATTR_READ_RE.finditer(scan):
            key = m.group(1)
            if "." in key and not key.endswith("."):
                keys.append(key)
        for m in _DICT_READ_RE.finditer(scan):
            keys.append(f'{m.group(1)}["{m.group(3)}"]')
        return keys

    # ------------------------------------------------------------------
    # 3. Function arg -> parameter uses in callee
    # ------------------------------------------------------------------

    def _add_call_edges(
        self,
        graph: nx.DiGraph,
        all_nodes: list[PDGNode],
        call_graph: ProjectCallGraph,
    ) -> int:
        # Build per-file variable def/use indices
        file_defs: dict[str, dict[str, list[PDGNode]]] = {}
        file_uses: dict[str, dict[str, list[PDGNode]]] = {}
        for node in all_nodes:
            f = node.file
            fd = file_defs.setdefault(f, {})
            fu = file_uses.setdefault(f, {})
            for v in node.variables_defined:
                fd.setdefault(v, []).append(node)
            for v in node.variables_used:
                fu.setdefault(v, []).append(node)

        added = 0
        for node in all_nodes:
            if node.node_type not in (
                NodeType.CALL, NodeType.STATEMENT, NodeType.EXPRESSION,
                NodeType.ASSIGNMENT, NodeType.RETURN,
            ):
                continue
            for func_name, arg_vars in self._parse_calls(node.code):
                callee_file = self._resolve_callee(
                    node.file, func_name, call_graph
                )
                if not callee_file:
                    continue
                fd_obj = call_graph.get_func_def(callee_file, func_name)
                if not fd_obj:
                    continue

                for arg_idx, arg_var in enumerate(arg_vars):
                    if arg_idx >= len(fd_obj.params):
                        break
                    param_name = fd_obj.params[arg_idx]
                    callee_uses = [
                        n for n in file_uses.get(callee_file, {}).get(param_name, [])
                        if n.line > fd_obj.start_line
                    ]
                    if not callee_uses:
                        continue

                    # Source nodes: direct definitions of the arg variable in caller
                    # Fall back to the call node itself for complex arg expressions
                    caller_defs = file_defs.get(node.file, {}).get(arg_var, [])
                    src_nodes = caller_defs if caller_defs else [node]

                    for sn in src_nodes:
                        for cn in callee_uses:
                            if not graph.has_edge(sn.id, cn.id):
                                graph.add_edge(sn.id, cn.id,
                                               edge_type=EdgeType.DATA_DEP,
                                               var=f"<arg:{func_name}:{param_name}>")
                                added += 1
        return added

    def _parse_calls(self, code: str) -> list[tuple[str, list[str]]]:
        results = []
        for m in _CALL_RE.finditer(code):
            fname = m.group(1)
            if fname in _KEYWORDS:
                continue
            args_raw = m.group(2).strip()
            if not args_raw:
                results.append((fname, []))
                continue
            args = [_last_ident(p.strip()) for p in args_raw.split(",")]
            results.append((fname, args))
        return results

    def _resolve_callee(
        self,
        caller_file: str,
        func_name: str,
        call_graph: ProjectCallGraph,
    ) -> Optional[str]:
        """Resolve a function name to the file that defines it.

        Returns None if the resolved file is a vendored / third-party file —
        taint should not cross the application / library boundary.
        """
        # 1. Import resolution (explicit)
        via_import = call_graph.resolve_import(caller_file, func_name)
        if via_import:
            if _is_third_party_file(via_import):
                log.debug("cross_file.skip_third_party", file=via_import)
                return None
            return via_import
        # 2. Any other file that defines this function name
        fd = call_graph.get_func_def_by_name(func_name)
        if fd and fd.file != caller_file:
            if _is_third_party_file(fd.file):
                log.debug("cross_file.skip_third_party", file=fd.file)
                return None
            return fd.file
        return None

    # ------------------------------------------------------------------
    # 4. Return value -> assignment at call site
    # ------------------------------------------------------------------

    def _add_return_edges(
        self,
        graph: nx.DiGraph,
        all_nodes: list[PDGNode],
        call_graph: ProjectCallGraph,
    ) -> int:
        # Map "callee_file:func_name" -> [return nodes]
        ret_map: dict[str, list[PDGNode]] = {}
        for node in all_nodes:
            if node.node_type == NodeType.RETURN:
                fn = self._enclosing_func(node, call_graph)
                if fn:
                    ret_map.setdefault(f"{node.file}:{fn}", []).append(node)

        added = 0
        for node in all_nodes:
            if node.node_type != NodeType.ASSIGNMENT:
                continue
            for m in _CALL_RE.finditer(node.code):
                fname = m.group(1)
                if fname in _KEYWORDS:
                    continue
                callee_file = self._resolve_callee(node.file, fname, call_graph)
                if not callee_file:
                    continue
                for ret_node in ret_map.get(f"{callee_file}:{fname}", []):
                    if not graph.has_edge(ret_node.id, node.id):
                        graph.add_edge(ret_node.id, node.id,
                                       edge_type=EdgeType.DATA_DEP,
                                       var=f"<return:{fname}>")
                        added += 1
        return added

    def _enclosing_func(
        self, node: PDGNode, call_graph: ProjectCallGraph
    ) -> Optional[str]:
        best_name: Optional[str] = None
        best_line = -1
        for fd in call_graph.func_defs.values():
            if fd.file == node.file and fd.start_line <= node.line > best_line:
                best_line = fd.start_line
                best_name = fd.name
        return best_name
