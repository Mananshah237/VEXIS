"""
Vulnerable: ORM used safely for most queries, but one raw db.execute() with f-string.
Expected: 1 finding, CWE-89. The ORM-safe queries must NOT be flagged.
"""
from flask import request
from myapp import db, User


@app.route("/user/<int:user_id>")
def get_user(user_id):
    # SAFE: ORM parameterized query — should not be flagged
    user = User.query.filter_by(id=user_id).first()
    return str(user)


@app.route("/report")
def report():
    report_type = request.args.get("type", "summary")
    # VULNERABLE: raw SQL with f-string
    result = db.execute(f"SELECT * FROM reports WHERE type = '{report_type}'")
    return str(list(result))
