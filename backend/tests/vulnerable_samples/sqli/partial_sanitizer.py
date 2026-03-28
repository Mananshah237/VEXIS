"""Vulnerable: SQL injection with a bypassable sanitizer (strips single quotes but not backslashes)"""
from flask import request
import sqlite3


def search_products():
    name = request.args.get("name", "")
    # Incomplete sanitization — strips quotes but backslash bypass still works
    # e.g. payload: \' OR 1=1 --
    sanitized = name.replace("'", "")
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    # STILL VULNERABLE: backslash can break out of string context
    query = f"SELECT * FROM products WHERE name = '{sanitized}'"
    cursor.execute(query)
    return cursor.fetchall()
