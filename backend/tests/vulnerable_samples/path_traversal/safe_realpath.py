"""Safe: Path traversal mitigated by realpath + prefix check"""
from flask import request
import os


ALLOWED_DIR = "/var/www/files"


def read_file():
    filename = request.args.get("file", "")
    # SAFE: resolve symlinks, then check prefix
    full_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    if not full_path.startswith(ALLOWED_DIR):
        return {"error": "Access denied"}
    with open(full_path) as f:
        return {"content": f.read()}
