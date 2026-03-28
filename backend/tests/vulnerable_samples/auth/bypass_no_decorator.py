"""CWE-287: Auth bypass — route accesses sensitive data without authentication"""
import sqlite3

# No @login_required!
@app.route("/admin/users")
def list_users():
    db = sqlite3.connect("app.db")
    users = db.execute("SELECT * FROM users").fetchall()  # Sensitive — no auth check
    return str(users)
