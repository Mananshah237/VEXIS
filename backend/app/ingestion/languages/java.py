"""
Java language support for VEXIS.

Java taint analysis is wired into the existing engine rather than a separate
module, in five places. Use this as the recipe for adding the next language
(Go, Ruby, C/C++, Rust, ...):

1. Grammar (parser.py)
   - Add a lazy `_get_<lang>_language()` that imports the tree-sitter binding.
   - Register the extension in `_EXT_MAP` and a branch in `CodeParser._get_parser`.

2. AST node types (pdg_builder.py)
   - Add the language's node-type names to `_classify_node`'s `type_map`
     (e.g. Java `local_variable_declaration` -> ASSIGNMENT,
     `method_invocation` -> CALL, `method_declaration` -> FUNCTION_DEF).
   - Extend `_extract_defined_vars` / `_extract_used_vars` / `_extract_calls`
     for any node types whose variable def/use shape differs.

3. Taint patterns (trust_boundaries.py)
   - Add `<LANG>_TAINT_SOURCES`, `<LANG>_TAINT_SINKS`, `<LANG>_SANITIZERS`.
   - Patterns are matched as substrings / word-boundary tokens against node
     code, and sanitizers carry a CCSM `constraint_power` + `effective_for`.

4. Engine wiring (taint/engine.py)
   - Import the new lists and concatenate them in `TaintEngine.__init__`.

5. Project scans (core/orchestrator.py) + deps (pyproject.toml)
   - Add the extension to the rglob discovery list.
   - Add the tree-sitter binding to dependencies.

Then add a `tests/vulnerable_samples/<class>/*.java` corpus (vulnerable + safe)
and a test module asserting detection and no false positives.

Note: a future refactor can move each language's (grammar, node-map, patterns)
into a self-contained LanguageProfile behind a registry; the data above already
isolates the language-specific knowledge so that move is mechanical.
"""
