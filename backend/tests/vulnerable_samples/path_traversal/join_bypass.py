"""
Vulnerable sample: Path Traversal via os.path.join bypass.
CWE-22 — Improper Limitation of a Pathname to a Restricted Directory.

Expected: VEXIS finds path traversal at open() with source at request.args.get("filename")

The subtle bug: os.path.join("/safe/dir", "/etc/passwd") returns "/etc/passwd"
because os.path.join discards the prefix when the second component is absolute.
A check like startswith("/safe/dir") on the joined path catches this,
but the code below skips that check.
"""
import os
from flask import Flask, request, send_file

app = Flask(__name__)

SAFE_DIR = "/var/app/files"


@app.route("/download")
def download():
    filename = request.args.get("filename")
    # VULNERABLE: os.path.join silently discards SAFE_DIR if filename starts with /
    # e.g., filename="/etc/passwd" -> full_path="/etc/passwd"
    full_path = os.path.join(SAFE_DIR, filename)
    return send_file(full_path)


@app.route("/read")
def read_file():
    name = request.args.get("name")
    base = "/app/static"
    path = os.path.join(base, name)
    # VULNERABLE: no realpath check, no startswith verification
    with open(path, "r") as f:
        return f.read()
