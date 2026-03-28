"""
Second-order SQL injection.
Attack flow: POST /register (safe parameterized INSERT) → GET /admin/lookup (reads from DB → uses in unsanitized SQL)
"""
from flask import request
import sqlite3

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    db = sqlite3.connect("app.db")
    db.execute("INSERT INTO users (name) VALUES (?)", (username,))  # Safe parameterized insert
    db.commit()
    return "Registered"

@app.route("/admin/lookup")
def admin_lookup():
    db = sqlite3.connect("app.db")
    user = db.execute("SELECT name FROM users ORDER BY id DESC LIMIT 1").fetchone()
    # Admin tool that trusts data from the DB — WRONG!
    details = db.execute(f"SELECT * FROM user_details WHERE name = '{user[0]}'")  # Second-order SQLi!
    return str(details.fetchall())
