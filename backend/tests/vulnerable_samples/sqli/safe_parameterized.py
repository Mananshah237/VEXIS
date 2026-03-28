"""Safe: Properly parameterized query — should NOT be flagged"""
from flask import request
import sqlite3


def search_users():
    name = request.args.get("name", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: parameterized query
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
