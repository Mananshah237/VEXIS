"""CWE-117 Safe: newlines stripped before logging"""
import logging
from flask import request

logger = logging.getLogger(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    safe_user = username.replace("\n", "").replace("\r", "")
    logger.warning(f"Login attempt: {safe_user}")  # SAFE: newlines removed
    return "ok"
