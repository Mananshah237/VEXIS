"""Vulnerable: SQL injection via f-string concatenation"""
from flask import request
import sqlite3


def search_users():
    name = request.args.get("name", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: user input directly in SQL
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
