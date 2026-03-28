"""
SAFE: parameterized query using ? placeholder.
The user input is passed as a separate parameter, never concatenated into the SQL string.
Expected: 0 findings (false positive check).
"""
import sqlite3
from flask import request


@app.route("/users")
def get_user():
    user_id = request.args.get("id", "")
    db = sqlite3.connect("app.db")
    # SAFE: parameterized — user_id is passed as a bound parameter, never interpolated
    db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return "ok"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    db = sqlite3.connect("app.db")
    # SAFE: %s-style parameterized
    db.execute("SELECT * FROM items WHERE name = %s", (query,))
    return "ok"
