"""
End-to-end tests against the vulnerable samples corpus.
Verifies the taint engine correctly identifies known vulnerabilities
and does NOT flag safe (false positive) samples.
"""
import pytest
from pathlib import Path

from app.ingestion.parser import CodeParser
from app.ingestion.pdg_builder import PDGBuilder
from app.taint.engine import TaintEngine

SAMPLES_DIR = Path(__file__).parent / "vulnerable_samples"


def scan_file(filepath: str) -> list:
    parser = CodeParser()
    pdg_builder = PDGBuilder()
    engine = TaintEngine()
    parsed = parser.parse_file(filepath)
    pdg = pdg_builder.build(parsed)
    return engine.analyze(pdg)


# ============================================================
# SQL INJECTION
# ============================================================

def test_sqli_fstring_detected():
    paths = scan_file(str(SAMPLES_DIR / "sqli/basic_fstring.py"))
    sqli = [p for p in paths if p.vuln_class == "sqli"]
    assert len(sqli) >= 1, "Expected to detect SQLi in fstring sample"
    assert sqli[0].confidence >= 0.6


def test_sqli_concatenation_detected():
    paths = scan_file(str(SAMPLES_DIR / "sqli/concatenation.py"))
    sqli = [p for p in paths if p.vuln_class == "sqli"]
    assert len(sqli) >= 1, "Expected to detect SQLi in concatenation sample"


def test_sqli_partial_sanitizer_detected():
    paths = scan_file(str(SAMPLES_DIR / "sqli/partial_sanitizer.py"))
    sqli = [p for p in paths if p.vuln_class == "sqli"]
    assert len(sqli) >= 1, "Expected to detect SQLi despite incomplete sanitizer"


def test_sqli_safe_parameterized_no_detection():
    paths = scan_file(str(SAMPLES_DIR / "sqli/safe_parameterized.py"))
    high_conf_sqli = [p for p in paths if p.vuln_class == "sqli" and p.confidence > 0.6]
    assert len(high_conf_sqli) == 0, f"False positive on safe parameterized query: {high_conf_sqli}"


# ============================================================
# COMMAND INJECTION
# ============================================================

def test_cmdi_os_system_detected():
    paths = scan_file(str(SAMPLES_DIR / "cmdi/os_system.py"))
    cmdi = [p for p in paths if p.vuln_class == "cmdi"]
    assert len(cmdi) >= 1, "Expected to detect CMDi in os.system sample"


def test_cmdi_subprocess_shell_detected():
    paths = scan_file(str(SAMPLES_DIR / "cmdi/subprocess_shell.py"))
    cmdi = [p for p in paths if p.vuln_class == "cmdi"]
    assert len(cmdi) >= 1, "Expected to detect CMDi in subprocess(shell=True) sample"


def test_cmdi_safe_shlex_no_high_conf_detection():
    paths = scan_file(str(SAMPLES_DIR / "cmdi/safe_shlex.py"))
    # shlex.quote is a sanitizer — confidence should be low or path cleared
    high_conf_cmdi = [p for p in paths if p.vuln_class == "cmdi" and p.confidence > 0.6]
    assert len(high_conf_cmdi) == 0, f"False positive on shlex.quote: {high_conf_cmdi}"


# ============================================================
# PATH TRAVERSAL
# ============================================================

def test_path_traversal_open_detected():
    paths = scan_file(str(SAMPLES_DIR / "path_traversal/open_direct.py"))
    pt = [p for p in paths if p.vuln_class == "path_traversal"]
    assert len(pt) >= 1, "Expected to detect path traversal in direct open() sample"


def test_path_traversal_safe_realpath_no_high_conf():
    paths = scan_file(str(SAMPLES_DIR / "path_traversal/safe_realpath.py"))
    high_conf_pt = [p for p in paths if p.vuln_class == "path_traversal" and p.confidence > 0.7]
    assert len(high_conf_pt) == 0, f"False positive on realpath-protected sample: {high_conf_pt}"
