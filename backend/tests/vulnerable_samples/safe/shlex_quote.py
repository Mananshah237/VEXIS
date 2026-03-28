"""
SAFE: shlex.quote() applied before passing user input to subprocess.
The sanitized value is shell-escaped, preventing command injection.
Expected: 0 findings (false positive check).
"""
import shlex
import subprocess
from flask import request


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # SAFE: shlex.quote() prevents command injection by properly shell-escaping the input
    safe_host = shlex.quote(host)
    result = subprocess.run(
        f"ping -c 1 {safe_host}", shell=True, capture_output=True, timeout=5
    )
    return result.stdout.decode()
