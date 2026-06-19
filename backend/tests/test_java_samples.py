"""
Java taint-analysis corpus tests.
Verifies VEXIS detects known Java vulnerabilities (SQLi, command injection,
path traversal, reflected XSS) and does NOT flag the safe counterparts.
"""
from pathlib import Path

from app.ingestion.parser import CodeParser
from app.ingestion.pdg_builder import PDGBuilder
from app.taint.engine import TaintEngine

SAMPLES_DIR = Path(__file__).parent / "vulnerable_samples"


def scan_file(rel_path: str) -> list:
    parser = CodeParser()
    pdg_builder = PDGBuilder()
    engine = TaintEngine()
    parsed = parser.parse_file(str(SAMPLES_DIR / rel_path))
    return engine.analyze(pdg_builder.build(parsed))


# ---- SQL injection ----------------------------------------------------------

def test_java_sqli_detected():
    paths = scan_file("sqli/SqlInjection.java")
    sqli = [p for p in paths if p.vuln_class == "sqli"]
    assert len(sqli) >= 1, "Expected SQLi in concatenated JDBC query"
    assert sqli[0].confidence >= 0.6


def test_java_sqli_safe_parameterized():
    paths = scan_file("sqli/SafeParameterized.java")
    high = [p for p in paths if p.vuln_class == "sqli" and p.confidence > 0.6]
    assert not high, f"False positive on PreparedStatement: {high}"


# ---- Command injection ------------------------------------------------------

def test_java_cmdi_detected():
    paths = scan_file("cmdi/CommandInjection.java")
    cmdi = [p for p in paths if p.vuln_class == "cmdi"]
    assert len(cmdi) >= 1, "Expected command injection in Runtime.exec"


def test_java_cmdi_safe_numeric():
    paths = scan_file("cmdi/SafeValidated.java")
    high = [p for p in paths if p.vuln_class == "cmdi" and p.confidence > 0.6]
    assert not high, f"False positive after Integer.parseInt: {high}"


# ---- Path traversal ---------------------------------------------------------

def test_java_path_traversal_detected():
    paths = scan_file("path_traversal/PathTraversal.java")
    pt = [p for p in paths if p.vuln_class == "path_traversal"]
    assert len(pt) >= 1, "Expected path traversal in new File(user input)"


def test_java_path_traversal_safe_filename():
    paths = scan_file("path_traversal/SafeFilename.java")
    high = [p for p in paths if p.vuln_class == "path_traversal" and p.confidence > 0.7]
    assert not high, f"False positive after FilenameUtils.getName: {high}"


# ---- Reflected XSS ----------------------------------------------------------

def test_java_xss_detected():
    paths = scan_file("xss/ReflectedXss.java")
    xss = [p for p in paths if p.vuln_class == "xss"]
    assert len(xss) >= 1, "Expected reflected XSS in response writer"


def test_java_xss_safe_encoded():
    paths = scan_file("xss/SafeEncoded.java")
    high = [p for p in paths if p.vuln_class == "xss" and p.confidence > 0.6]
    assert not high, f"False positive after HtmlUtils.htmlEscape: {high}"
