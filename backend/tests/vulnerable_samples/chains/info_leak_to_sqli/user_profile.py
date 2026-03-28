"""
Chain discovery test: info_leak_to_sqli

Two individually-medium findings that chain into a CRITICAL attack:
  Path 1: SQLi in SELECT leaks entire user row into session (info disclosure)
  Path 2: SQLi in UPDATE gated behind admin check — but the admin flag
          came from the attacker-controlled leak in Path 1

The CHAIN: attacker uses Path 1 to find the admin user_id, then uses
Path 2's SQLi to escalate their own role to admin.
"""
from flask import request, session
import sqlite3


app = None  # injected by Flask factory


@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    db = sqlite3.connect("app.db")
    # Low severity: information disclosure — returns raw DB data including internal IDs
    # FINDING 1: SQLi in f-string, info-disclosure class
    row = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    session["last_viewed_user"] = row  # stores entire row including admin flag
    return str(row)


@app.route("/update-role")
def update_role():
    user_data = session.get("last_viewed_user")
    if user_data and user_data[3] == "admin":
        new_role = request.args.get("role")
        db = sqlite3.connect("app.db")
        # FINDING 2: SQLi in UPDATE, gated behind admin check from session
        db.execute(f"UPDATE users SET role = '{new_role}' WHERE id = {user_data[0]}")
        db.commit()
        return "Updated"
    return "Forbidden", 403
