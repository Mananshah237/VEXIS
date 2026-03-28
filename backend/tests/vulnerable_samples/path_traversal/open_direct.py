"""Vulnerable: Path traversal via direct file open"""
from flask import request


def read_file():
    filename = request.args.get("file", "")
    # VULNERABLE: user controls file path
    with open(f"/var/www/files/{filename}") as f:
        return f.read()
