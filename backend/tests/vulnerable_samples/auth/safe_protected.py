"""CWE-287 Safe: route uses @login_required"""
from flask_login import login_required
import sqlite3

@app.route("/admin/users")
@login_required  # Protected
def list_users():
    db = sqlite3.connect("app.db")
    users = db.execute("SELECT * FROM users").fetchall()
    return str(users)
