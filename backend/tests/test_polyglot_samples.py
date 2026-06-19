"""
Multi-language taint-analysis corpus tests (Go, Ruby, C/C++, Rust, Bash).
Verifies VEXIS detects known vulnerabilities in each language and clears the
safe counterparts.
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


def has(paths, vuln_class):
    return [p for p in paths if p.vuln_class == vuln_class]


# ---- Go ---------------------------------------------------------------------

def test_go_sqli_detected():
    assert has(scan_file("sqli/go_sqli.go"), "sqli"), "Expected SQLi in Go db.Query"


def test_go_sqli_safe():
    high = [p for p in scan_file("sqli/go_safe.go") if p.vuln_class == "sqli" and p.confidence > 0.6]
    assert not high, f"False positive after strconv.Atoi: {high}"


def test_go_cmdi_detected():
    assert has(scan_file("cmdi/go_cmdi.go"), "cmdi"), "Expected command injection in Go exec.Command"


# ---- Ruby -------------------------------------------------------------------

def test_ruby_sqli_detected():
    assert has(scan_file("sqli/ruby_sqli.rb"), "sqli"), "Expected SQLi in Ruby connection.execute"


def test_ruby_sqli_safe():
    high = [p for p in scan_file("sqli/ruby_safe.rb") if p.vuln_class == "sqli" and p.confidence > 0.6]
    assert not high, f"False positive after to_i: {high}"


def test_ruby_cmdi_detected():
    assert has(scan_file("cmdi/ruby_cmdi.rb"), "cmdi"), "Expected command injection in Ruby system()"


# ---- C / C++ ----------------------------------------------------------------

def test_c_cmdi_detected():
    assert has(scan_file("cmdi/c_cmdi.c"), "cmdi"), "Expected command injection in C system()"


def test_c_buffer_overflow_detected():
    assert has(scan_file("buffer_overflow/c_overflow.c"), "buffer_overflow"), \
        "Expected buffer overflow in C strcpy()"


def test_c_buffer_overflow_safe():
    high = [p for p in scan_file("buffer_overflow/c_safe.c")
            if p.vuln_class == "buffer_overflow" and p.confidence > 0.6]
    assert not high, f"False positive after atoi/snprintf: {high}"


# ---- Rust -------------------------------------------------------------------

def test_rust_cmdi_detected():
    assert has(scan_file("cmdi/rust_cmdi.rs"), "cmdi"), "Expected command injection in Rust Command::new"


def test_rust_cmdi_safe():
    high = [p for p in scan_file("cmdi/rust_safe.rs") if p.vuln_class == "cmdi" and p.confidence > 0.6]
    assert not high, f"False positive after parse::<i32>: {high}"


# ---- Bash -------------------------------------------------------------------

def test_bash_cmdi_detected():
    assert has(scan_file("cmdi/bash_cmdi.sh"), "cmdi"), "Expected command injection in Bash eval"


def test_bash_cmdi_safe():
    assert not has(scan_file("cmdi/bash_safe.sh"), "cmdi"), "No eval — should be clean"
