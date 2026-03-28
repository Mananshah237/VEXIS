"""
Project-wide function call graph.
Resolves imports and maps function definitions across files.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.ingestion.parser import ParsedFile


@dataclass
class FuncDef:
    """A function definition extracted from a parsed file."""
    file: str
    name: str
    params: list[str]   # parameter names in declaration order (excluding 'self')
    start_line: int     # 0-indexed line of 'def' keyword


class ProjectCallGraph:
    """
    Project-wide view of function definitions and import resolutions.
    Used by CrossFileLinker to inject interprocedural DATA_DEP edges.
    """
    def __init__(self) -> None:
        # "file_path:func_name" -> FuncDef
        self.func_defs: dict[str, FuncDef] = {}
        # file_path -> {local_name_used_in_file -> source_module_stem}
        self.imports: dict[str, dict[str, str]] = {}
        # module stem -> resolved file path
        self.module_files: dict[str, str] = {}

    def get_func_def(self, file: str, func_name: str) -> Optional[FuncDef]:
        return self.func_defs.get(f"{file}:{func_name}")

    def get_func_def_by_name(self, func_name: str) -> Optional[FuncDef]:
        for fd in self.func_defs.values():
            if fd.name == func_name:
                return fd
        return None

    def resolve_import(self, from_file: str, local_name: str) -> Optional[str]:
        """Return the file path defining local_name, or None if not resolvable."""
        module_stem = self.imports.get(from_file, {}).get(local_name)
        if not module_stem:
            return None
        return self.module_files.get(module_stem)


class CallGraphBuilder:
    """Builds a ProjectCallGraph from a list of ParsedFiles."""

    def build_project(
        self,
        parsed_files: list[ParsedFile],
        project_root: str = "",
    ) -> ProjectCallGraph:
        cg = ProjectCallGraph()

        # Register module stem -> file path
        for pf in parsed_files:
            stem = Path(pf.path).stem
            cg.module_files[stem] = pf.path

        # Extract function defs and imports from each file
        for pf in parsed_files:
            cg.imports.setdefault(pf.path, {})
            self._extract_from_file(pf, cg)

        return cg

    def _extract_from_file(self, pf: ParsedFile, cg: ProjectCallGraph) -> None:
        self._walk(pf.root, pf, cg)

    def _walk(self, node, pf: ParsedFile, cg: ProjectCallGraph) -> None:
        t = node.type

        if t == "function_definition":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = pf.node_text(name_node)
                params = self._extract_params(params_node, pf) if params_node else []
                cg.func_defs[f"{pf.path}:{name}"] = FuncDef(
                    file=pf.path, name=name, params=params,
                    start_line=node.start_point[0],
                )
            for child in node.children:
                self._walk(child, pf, cg)
            return

        if t == "import_from_statement":
            # from module import name [as alias], ...
            module_node = node.child_by_field_name("module_name")
            if module_node:
                module_stem = pf.node_text(module_node).split(".")[-1]
                module_text = pf.node_text(module_node)
                for child in node.children:
                    if child.type == "dotted_name":
                        name = pf.node_text(child)
                        if name != module_text:
                            cg.imports[pf.path][name] = module_stem
                    elif child.type == "aliased_import":
                        alias_node = child.child_by_field_name("alias")
                        orig_node = child.child_by_field_name("name")
                        if alias_node:
                            cg.imports[pf.path][pf.node_text(alias_node)] = module_stem
                        elif orig_node:
                            cg.imports[pf.path][pf.node_text(orig_node)] = module_stem

        elif t == "import_statement":
            # import module [as alias]
            for child in node.children:
                if child.type == "dotted_name":
                    name = pf.node_text(child)
                    cg.imports[pf.path][name] = name.split(".")[-1]
                elif child.type == "aliased_import":
                    orig = child.child_by_field_name("name")
                    alias = child.child_by_field_name("alias")
                    if orig:
                        stem = pf.node_text(orig).split(".")[-1]
                        local = pf.node_text(alias) if alias else pf.node_text(orig)
                        cg.imports[pf.path][local] = stem

        for child in node.children:
            self._walk(child, pf, cg)

    def _extract_params(self, params_node, pf: ParsedFile) -> list[str]:
        params: list[str] = []
        for child in params_node.children:
            ct = child.type
            if ct == "identifier":
                name = pf.node_text(child)
                if name != "self":
                    params.append(name)
            elif ct in ("typed_parameter", "default_parameter",
                        "typed_default_parameter", "list_splat_pattern",
                        "dictionary_splat_pattern"):
                for sub in child.children:
                    if sub.type == "identifier":
                        name = pf.node_text(sub)
                        if name != "self":
                            params.append(name)
                            break
        return params


# Legacy compatibility shim
class CallGraph:
    pass
