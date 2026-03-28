"""
Safe template rendering — name is passed as context variable, NOT injected into template string.
Expected: 0 findings (false positive check).
"""
from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # render_template uses a static template file — Jinja2 auto-escapes context vars
    return render_template("greet.html", name=name)
