"""
Vulnerable: Flask send_file() with unsanitized user-controlled filename.
No validation, no realpath check, no prefix check.
Expected: 1 finding, CWE-22, HIGH.
"""
from flask import request, send_file


@app.route("/download")
def download():
    # VULNERABLE: attacker can request any file on the filesystem
    # Payload: ../../../../etc/passwd
    file_path = request.args.get("file", "")
    return send_file(file_path)
