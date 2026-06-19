"""
Tree-sitter based source code parser.
Supports Python, JavaScript, TypeScript, JSX, TSX.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

PY_LANGUAGE = Language(tspython.language())

# Lazy-load JS/TS/Java grammars to avoid import errors if not installed
_JS_LANGUAGE: Language | None = None
_TS_LANGUAGE: Language | None = None
_TSX_LANGUAGE: Language | None = None
_JAVA_LANGUAGE: Language | None = None


def _get_js_language() -> Language:
    global _JS_LANGUAGE
    if _JS_LANGUAGE is None:
        import tree_sitter_javascript as tsjs
        _JS_LANGUAGE = Language(tsjs.language())
    return _JS_LANGUAGE


def _get_ts_language() -> Language:
    global _TS_LANGUAGE
    if _TS_LANGUAGE is None:
        import tree_sitter_typescript as tsts
        _TS_LANGUAGE = Language(tsts.language_typescript())
    return _TS_LANGUAGE


def _get_tsx_language() -> Language:
    global _TSX_LANGUAGE
    if _TSX_LANGUAGE is None:
        import tree_sitter_typescript as tsts
        _TSX_LANGUAGE = Language(tsts.language_tsx())
    return _TSX_LANGUAGE


def _get_java_language() -> Language:
    global _JAVA_LANGUAGE
    if _JAVA_LANGUAGE is None:
        import tree_sitter_java as tsjava
        _JAVA_LANGUAGE = Language(tsjava.language())
    return _JAVA_LANGUAGE


# Additional grammars, each lazily loaded so a missing binding only disables
# that one language instead of breaking import.
_LAZY_LANGS: dict[str, Language] = {}


def _lazy(name: str, importer) -> Language:
    if name not in _LAZY_LANGS:
        _LAZY_LANGS[name] = Language(importer())
    return _LAZY_LANGS[name]


def _get_go_language() -> Language:
    import tree_sitter_go as ts
    return _lazy("go", ts.language)


def _get_ruby_language() -> Language:
    import tree_sitter_ruby as ts
    return _lazy("ruby", ts.language)


def _get_c_language() -> Language:
    import tree_sitter_c as ts
    return _lazy("c", ts.language)


def _get_cpp_language() -> Language:
    import tree_sitter_cpp as ts
    return _lazy("cpp", ts.language)


def _get_rust_language() -> Language:
    import tree_sitter_rust as ts
    return _lazy("rust", ts.language)


def _get_bash_language() -> Language:
    import tree_sitter_bash as ts
    return _lazy("bash", ts.language)


# Map file extension → (language_name, language_getter). Single source of truth
# for which extensions VEXIS can parse.
_EXT_MAP: dict[str, tuple[str, Any]] = {
    ".py": ("python", lambda: PY_LANGUAGE),
    ".js": ("javascript", _get_js_language),
    ".jsx": ("javascript", _get_js_language),
    ".ts": ("typescript", _get_ts_language),
    ".tsx": ("typescript", _get_tsx_language),
    ".java": ("java", _get_java_language),
    ".go": ("go", _get_go_language),
    ".rb": ("ruby", _get_ruby_language),
    ".c": ("c", _get_c_language),
    ".h": ("c", _get_c_language),
    ".cpp": ("cpp", _get_cpp_language),
    ".cc": ("cpp", _get_cpp_language),
    ".cxx": ("cpp", _get_cpp_language),
    ".hpp": ("cpp", _get_cpp_language),
    ".rs": ("rust", _get_rust_language),
    ".sh": ("bash", _get_bash_language),
    ".bash": ("bash", _get_bash_language),
}


@dataclass
class ParsedFile:
    path: str
    source: str
    source_bytes: bytes
    tree: Any  # tree_sitter.Tree
    language: str = "python"

    @property
    def root(self) -> Node:
        return self.tree.root_node

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    def get_line(self, line_num: int) -> str:
        lines = self.lines
        if 0 <= line_num < len(lines):
            return lines[line_num]
        return ""

    def node_text(self, node: Node) -> str:
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


class CodeParser:
    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def _get_parser(self, language: str) -> Parser:
        if language not in self._parsers:
            if language == "python":
                self._parsers[language] = Parser(PY_LANGUAGE)
            elif language == "javascript":
                self._parsers[language] = Parser(_get_js_language())
            elif language == "typescript":
                self._parsers[language] = Parser(_get_ts_language())
            elif language == "tsx":
                self._parsers[language] = Parser(_get_tsx_language())
            elif language == "java":
                self._parsers[language] = Parser(_get_java_language())
            elif language == "go":
                self._parsers[language] = Parser(_get_go_language())
            elif language == "ruby":
                self._parsers[language] = Parser(_get_ruby_language())
            elif language == "c":
                self._parsers[language] = Parser(_get_c_language())
            elif language == "cpp":
                self._parsers[language] = Parser(_get_cpp_language())
            elif language == "rust":
                self._parsers[language] = Parser(_get_rust_language())
            elif language == "bash":
                self._parsers[language] = Parser(_get_bash_language())
            else:
                self._parsers[language] = Parser(PY_LANGUAGE)
        return self._parsers[language]

    def _detect_language(self, path: str) -> str:
        ext = Path(path).suffix.lower()
        lang_info = _EXT_MAP.get(ext)
        if lang_info:
            return lang_info[0]
        return "python"  # default fallback

    def parse_file(self, path: str) -> ParsedFile:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.parse_code(source, path=path)

    def parse_code(self, code: str, path: str = "<string>") -> ParsedFile:
        language = self._detect_language(path)
        parser = self._get_parser(language)
        encoded = code.encode("utf-8")
        tree = parser.parse(encoded)
        return ParsedFile(path=path, source=code, source_bytes=encoded, tree=tree, language=language)
