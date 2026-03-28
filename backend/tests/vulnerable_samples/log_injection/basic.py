"""CWE-117: Log injection — user input logged without sanitization"""
import logging
from flask import request

logger = logging.getLogger(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    logger.warning(f"Login attempt: {username}")  # VULNERABLE: log injection
    return "ok"
