"""Detection-quality regressions for the review findings F08-F14.

Run from the backend working directory (as CI does) so `app` is importable.
These exercise the taint engine, PDG scoping, sanitizer context-sensitivity,
second-order table identity, ingestion integrity, and discovery wiring.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.analysis.second_order import analyze_second_order
from app.core.orchestrator import _safe_relative_path, _write_raw_code
from app.exploit.script_generator import (
    _DEFAULT_TEMPLATE,
    _TEMPLATES,
    _string_body,
)
from app.ingestion.parser import CodeParser
from app.ingestion.pdg_builder import PDGBuilder
from app.models.schemas import ScanConfig
from app.taint.engine import TaintEngine


def _paths(code: str, name: str = "probe.py"):
    parsed = CodeParser().parse_code(code, path=name)
    return TaintEngine().analyze(PDGBuilder().build(parsed))


def _classes(paths):
    return sorted(p.vuln_class for p in paths)


# ── F08: source/sink matching must not depend on the receiver variable name ──
@pytest.mark.parametrize("handle", ["cursor", "conn", "connection", "my_database", "db", "session"])
def test_sql_sink_receiver_agnostic(handle):
    code = (
        "from flask import request\n"
        "def route():\n"
        "    q = request.args.get('q')\n"
        f"    {handle}.execute(f\"SELECT * FROM users WHERE name = '{{q}}'\")\n"
    )
    assert "sqli" in _classes(_paths(code)), f"{handle}.execute should be detected as a SQL sink"


def test_parameterized_query_is_not_flagged():
    code = (
        "from flask import request\n"
        "def route():\n"
        "    q = request.args.get('q')\n"
        "    cursor.execute('SELECT * FROM users WHERE name = %s', (q,))\n"
    )
    assert _classes(_paths(code)) == []


# ── F09: sanitizer effect must be context-sensitive to the sink class ──
def test_html_escape_does_not_clear_sql_injection():
    code = (
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    q = request.args.get('q')\n"
        "    x = html.escape(q)\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {x}')\n"
    )
    assert "sqli" in _classes(_paths(code))


def test_html_escape_still_clears_xss():
    code = (
        "from flask import request\n"
        "import html\n"
        "def route():\n"
        "    q = request.args.get('q')\n"
        "    x = html.escape(q)\n"
        "    return f'<div>{x}</div>'\n"
    )
    assert "xss" not in _classes(_paths(code))


# ── F10: PDG must not conflate identically-named locals in different functions ──
def test_distinct_function_scopes_do_not_conflate_variables():
    code = (
        "from flask import request\n"
        "def collect():\n"
        "    value = request.args.get('x')\n"
        "    return value\n"
        "def health():\n"
        "    value = 'ok'\n"
        "    cursor.execute(value)\n"
    )
    assert _paths(code) == [], "unrelated same-named locals must not create a taint path"


def test_intra_function_flow_still_detected():
    code = (
        "from flask import request\n"
        "def route():\n"
        "    q = request.args.get('q')\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{q}'\")\n"
    )
    assert "sqli" in _classes(_paths(code))


# ── F12: second-order findings require table identity, not proximity ──
def test_second_order_ignores_constant_queries_near_reads():
    code = (
        "from flask import request\n"
        "def save():\n"
        "    x = request.form.get('x')\n"
        "    db.execute('INSERT INTO logs VALUES (?)', (x,))\n"
        "def health():\n"
        "    db.execute('SELECT 1')\n"
        "    row = db.fetchone()\n"
        "    db.execute('SELECT 2')\n"
        "    return 'ok'\n"
    )
    assert analyze_second_order([CodeParser().parse_code(code, path="safe.py")]) == []


def test_second_order_reports_matching_table_flow():
    code = (
        "from flask import request\n"
        "def save():\n"
        "    name = request.form.get('name')\n"
        "    db.execute('INSERT INTO users (name) VALUES (?)', (name,))\n"
        "def show():\n"
        "    db.execute('SELECT name FROM users WHERE id=1')\n"
        "    row = db.fetchone()\n"
        "    db.execute(f\"SELECT * FROM audit WHERE u = '{row[0]}'\")\n"
    )
    findings = analyze_second_order([CodeParser().parse_code(code, path="app.py")])
    assert len(findings) == 1
    assert findings[0].vuln_class == "sqli"
    assert findings[0].db_table.lower() == "users"


# ── F14: raw-code ingestion preserves paths and language identity ──
def test_multi_file_ingestion_preserves_paths_and_extensions():
    code = (
        "# === FILE: a/routes.py ===\nx = 1\n"
        "# === FILE: b/routes.py ===\nx = 2\n"
        "# === FILE: Example.java ===\nclass Example {}\n"
    )
    with tempfile.TemporaryDirectory() as d:
        _write_raw_code(code, d, None)
        got = {
            str(p.relative_to(d)).replace("\\", "/"): p.read_text().strip()
            for p in Path(d).rglob("*")
            if p.is_file()
        }
    assert got == {
        "a/routes.py": "x = 1",
        "b/routes.py": "x = 2",
        "Example.java": "class Example {}",
    }


def test_single_snippet_honors_declared_language():
    with tempfile.TemporaryDirectory() as d:
        _write_raw_code("class X {}", d, "java")
        assert [p.name for p in Path(d).iterdir()] == ["scan_target.java"]


@pytest.mark.parametrize("bad", ["../evil.py", "/etc/passwd", "a/../../x.py"])
def test_path_traversal_rejected(bad):
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError):
            _safe_relative_path(bad, d)


def test_unsupported_extension_rejected():
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError):
            _write_raw_code("# === FILE: x.exe ===\nhi\n", d, None)


def test_duplicate_paths_rejected():
    code = "# === FILE: a.py ===\nx=1\n# === FILE: a.py ===\nx=2\n"
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError):
            _write_raw_code(code, d, None)


# ── F13: discovery mode is accepted through the public request schema ──
def test_scan_config_accepts_discovery_mode():
    assert ScanConfig.model_validate({"discovery_mode": True}).discovery_mode is True
    assert ScanConfig().discovery_mode is False


# ── F18: every exploit template, including the generic default, is valid Python ──
def test_all_exploit_templates_produce_valid_python():
    import ast

    for cwe, template in {**_TEMPLATES, "default": _DEFAULT_TEMPLATE}.items():
        script = template.format(
            target_url=_string_body("http://example.invalid"),
            endpoint=_string_body("/test"),
            payload=_string_body("probe'\"x"),
            param="q",
            vuln_class=_string_body("probe"),
        )
        ast.parse(script)  # raises if the template is malformed
