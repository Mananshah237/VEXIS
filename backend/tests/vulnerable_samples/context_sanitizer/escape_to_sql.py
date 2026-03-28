"""
Context-sensitive sanitizer test.

html.escape() / markupsafe.escape() is effective for XSS — but does NOT protect against SQLi.
VEXIS must:
  - DETECT the SQLi (escape() doesn't protect SQL)
  - NOT detect XSS (escape() does protect against XSS in the HTML response)
"""
from flask import request
from markupsafe import escape
import sqlite3


@app.route("/search")
def search():
    q = request.args.get("q")
    safe_q = escape(q)  # Effective for XSS, NOT for SQLi
    db = sqlite3.connect("app.db")
    # VULNERABLE: safe_q is escaped for HTML but still injectable into SQL
    db.execute(f"SELECT * FROM items WHERE name = '{safe_q}'")
    return f"<h1>Results for: {safe_q}</h1>"
