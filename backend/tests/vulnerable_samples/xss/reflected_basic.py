"""
Reflected XSS via Markup() — CWE-79 HIGH
Attacker-controlled input rendered as raw HTML via Jinja2 Markup.
"""
from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Markup() marks the string as safe — bypasses Jinja2 auto-escaping
    return Markup(f"<h1>Hello, {name}!</h1>")
