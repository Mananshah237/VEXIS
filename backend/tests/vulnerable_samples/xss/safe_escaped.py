"""
Safe XSS mitigation — user input HTML-escaped before inclusion in response.
Expected: 0 findings (false positive check).
"""
import html
from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    safe_name = html.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"
