"""
Second-order stored XSS.
Attack flow: POST /comment (parameterized INSERT looks safe) → GET /comments (SELECT + render unsanitized HTML)
The INSERT uses parameterized query so normal SQLi detection won't fire.
VEXIS should detect the stored XSS path: HTTP input → DB write → DB read → unescaped HTML output.
"""
from flask import request, render_template_string
import sqlite3

@app.route("/comment", methods=["POST"])
def add_comment():
    comment = request.form.get("comment")
    db = sqlite3.connect("app.db")
    db.execute("INSERT INTO comments (text) VALUES (?)", (comment,))  # Parameterized — looks safe!
    db.commit()
    return "Saved"

@app.route("/comments")
def show_comments():
    db = sqlite3.connect("app.db")
    comments = db.execute("SELECT text FROM comments").fetchall()
    html = "<h1>Comments</h1>"
    for row in comments:
        html += f"<p>{row[0]}</p>"  # VULNERABLE: Stored XSS — DB data rendered in HTML
    return html
