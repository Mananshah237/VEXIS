"""
Program Dependency Graph builder.
Constructs a NetworkX DiGraph representing data and control dependencies.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import networkx as nx
from tree_sitter import Node

from app.ingestion.parser import ParsedFile


class NodeType(str, Enum):
    STATEMENT = "statement"
    EXPRESSION = "expression"
    CALL = "call"
    ASSIGNMENT = "assignment"
    CONDITION = "condition"
    RETURN = "return"
    PARAMETER = "parameter"
    IMPORT = "import"
    FUNCTION_DEF = "function_def"


class EdgeType(str, Enum):
    DATA_DEP = "data_dep"
    CONTROL_DEP = "control_dep"
    CALL_DEP = "call_dep"


@dataclass
class PDGNode:
    id: str
    node_type: NodeType
    label: str
    file: str
    line: int
    col: int
    code: str
    ast_node: Any = field(repr=False, default=None)
    variables_defined: list[str] = field(default_factory=list)
    variables_used: list[str] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)


class PDG:
    def __init__(self, graph: nx.DiGraph, file: str) -> None:
        self.graph = graph
        self.file = file

    def nodes(self) -> list[PDGNode]:
        return [self.graph.nodes[n]["data"] for n in self.graph.nodes]

    def get_successors(self, node: PDGNode) -> list[PDGNode]:
        return [self.graph.nodes[s]["data"] for s in self.graph.successors(node.id)]

    def get_data_successors(self, node: PDGNode) -> list[PDGNode]:
        return [
            self.graph.nodes[s]["data"]
            for s in self.graph.successors(node.id)
            if self.graph.edges[node.id, s].get("edge_type") == EdgeType.DATA_DEP
        ]


class PDGBuilder:
    def build(self, parsed: ParsedFile) -> PDG:
        graph = nx.DiGraph()
        self._parsed = parsed
        self._counter = 0
        self._var_defs: dict[str, list[str]] = {}  # var_name -> [node_ids]

        root = parsed.root
        self._visit_node(graph, root, parent_id=None)
        self._add_data_deps(graph)

        return PDG(graph=graph, file=parsed.path)

    def _next_id(self) -> str:
        self._counter += 1
        return f"n{self._counter}"

    def _visit_node(self, graph: nx.DiGraph, node: Any, parent_id: Optional[str]) -> Optional[str]:
        node_type = self._classify_node(node)
        if node_type is None:
            for child in node.children:
                self._visit_node(graph, child, parent_id)
            return None

        node_id = self._next_id()
        code = self._parsed.node_text(node)
        pdg_node = PDGNode(
            id=node_id,
            node_type=node_type,
            label=node.type,
            file=self._parsed.path,
            line=node.start_point[0],
            col=node.start_point[1],
            code=code,
            ast_node=node,
            variables_defined=self._extract_defined_vars(node),
            variables_used=self._extract_used_vars(node),
            function_calls=self._extract_calls(node),
        )
        graph.add_node(node_id, data=pdg_node)

        # Track variable definitions
        for var in pdg_node.variables_defined:
            if var not in self._var_defs:
                self._var_defs[var] = []
            self._var_defs[var].append(node_id)

        if parent_id:
            graph.add_edge(parent_id, node_id, edge_type=EdgeType.CONTROL_DEP)

        for child in node.children:
            self._visit_node(graph, child, node_id)

        return node_id

    def _add_data_deps(self, graph: nx.DiGraph) -> None:
        for node_id in graph.nodes:
            pdg_node: PDGNode = graph.nodes[node_id]["data"]
            for var in pdg_node.variables_used:
                if var in self._var_defs:
                    for def_id in self._var_defs[var]:
                        if def_id != node_id:
                            graph.add_edge(def_id, node_id, edge_type=EdgeType.DATA_DEP, var=var)

    def _classify_node(self, node: Any) -> Optional[NodeType]:
        type_map = {
            # Python
            "assignment": NodeType.ASSIGNMENT,
            "augmented_assignment": NodeType.ASSIGNMENT,
            "call": NodeType.CALL,
            "return_statement": NodeType.RETURN,
            "if_statement": NodeType.CONDITION,
            "while_statement": NodeType.CONDITION,
            "for_statement": NodeType.STATEMENT,
            "expression_statement": NodeType.STATEMENT,
            "function_definition": NodeType.FUNCTION_DEF,
            "parameters": NodeType.PARAMETER,
            "import_statement": NodeType.IMPORT,
            "import_from_statement": NodeType.IMPORT,
            # JavaScript / TypeScript
            "variable_declaration": NodeType.ASSIGNMENT,
            "lexical_declaration": NodeType.ASSIGNMENT,  # const/let
            "assignment_expression": NodeType.ASSIGNMENT,
            "call_expression": NodeType.CALL,
            "for_in_statement": NodeType.STATEMENT,
            "function_declaration": NodeType.FUNCTION_DEF,
            "function_expression": NodeType.FUNCTION_DEF,
            "arrow_function": NodeType.FUNCTION_DEF,
            "method_definition": NodeType.FUNCTION_DEF,
            "formal_parameters": NodeType.PARAMETER,
            "import_declaration": NodeType.IMPORT,
        }
        return type_map.get(node.type)

    def _extract_defined_vars(self, node: Any) -> list[str]:
        vars_: list[str] = []
        if node.type in ("assignment", "augmented_assignment", "assignment_expression"):
            left = node.child_by_field_name("left")
            if left and left.type == "identifier":
                vars_.append(self._parsed.node_text(left))
        elif node.type == "for_statement":
            left = node.child_by_field_name("left")
            if left and left.type == "identifier":
                vars_.append(self._parsed.node_text(left))
        elif node.type in ("variable_declaration", "lexical_declaration"):
            # JS: const x = ..., let y = ...
            for child in node.children:
                if child.type == "variable_declarator":
                    name = child.child_by_field_name("name")
                    if name and name.type == "identifier":
                        vars_.append(self._parsed.node_text(name))
                    # Destructuring: const { id } = req.query
                    elif name and name.type in ("object_pattern", "array_pattern"):
                        for sub in name.children:
                            if sub.type in ("shorthand_property_identifier_pattern", "identifier"):
                                vars_.append(self._parsed.node_text(sub))
        return vars_

    def _extract_used_vars(self, node: Any) -> list[str]:
        vars_: list[str] = []
        def collect(n: Any) -> None:
            if n.type == "identifier" and n.parent and n.parent.type not in ("function_definition",):
                vars_.append(self._parsed.node_text(n))
            for child in n.children:
                collect(child)
        if node.type in ("call", "return_statement", "expression_statement"):
            collect(node)
        elif node.type == "assignment":
            right = node.child_by_field_name("right")
            if right:
                collect(right)
        return list(set(vars_))

    def _extract_calls(self, node: Any) -> list[str]:
        calls: list[str] = []
        def collect(n: Any) -> None:
            if n.type == "call":
                func = n.child_by_field_name("function")
                if func:
                    calls.append(self._parsed.node_text(func))
            for child in n.children:
                collect(child)
        collect(node)
        return calls
