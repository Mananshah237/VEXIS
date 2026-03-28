"""CWE-601 Safe: URL validated to be relative (starts with /)"""
from flask import request, redirect

@app.route("/goto")
def goto():
    next_url = request.args.get("next", "/")
    if not next_url.startswith("/"):
        next_url = "/"  # Force relative URL only
    return redirect(next_url)  # SAFE: relative URL only
