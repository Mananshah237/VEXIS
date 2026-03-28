import pytest
from app.ingestion.parser import CodeParser
from app.ingestion.pdg_builder import PDGBuilder
from app.taint.engine import TaintEngine


SQLI_CODE = '''
from flask import request
import sqlite3

def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
'''

SAFE_CODE = '''
from flask import request
import sqlite3

def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
'''


def test_sqli_detected():
    parser = CodeParser()
    pdg_builder = PDGBuilder()
    engine = TaintEngine()

    parsed = parser.parse_code(SQLI_CODE, path="test.py")
    pdg = pdg_builder.build(parsed)
    paths = engine.analyze(pdg)

    sqli_paths = [p for p in paths if p.vuln_class == "sqli"]
    assert len(sqli_paths) >= 1, f"Expected SQLi finding, got paths: {paths}"


def test_safe_code_no_sqli():
    parser = CodeParser()
    pdg_builder = PDGBuilder()
    engine = TaintEngine()

    parsed = parser.parse_code(SAFE_CODE, path="test.py")
    pdg = pdg_builder.build(parsed)
    paths = engine.analyze(pdg)

    sqli_paths = [p for p in paths if p.vuln_class == "sqli"]
    # Safe code should have 0 (or low confidence) paths
    high_conf_sqli = [p for p in sqli_paths if p.confidence > 0.6]
    assert len(high_conf_sqli) == 0, f"False positive: {high_conf_sqli}"
