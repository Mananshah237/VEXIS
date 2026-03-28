"""
Vulnerable sample: SQL Injection via string concatenation.
CWE-89 — Improper Neutralization of Special Elements used in an SQL Command.

Expected: VEXIS finds SQLi at db.execute() with source at request.args.get("id")
"""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    db = sqlite3.connect("app.db")
    # VULNERABLE: string concatenation builds raw SQL with user input
    query = "SELECT * FROM users WHERE id=" + user_id
    result = db.execute(query)
    rows = result.fetchall()
    return jsonify(rows)


@app.route("/product")
def get_product():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    # VULNERABLE: also via concatenation, different sink pattern
    db.execute("SELECT * FROM products WHERE name='" + name + "'")
    return "ok"
