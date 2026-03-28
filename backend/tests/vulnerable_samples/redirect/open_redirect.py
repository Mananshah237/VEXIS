"""CWE-601: Open Redirect — user-controlled URL passed to redirect()"""
from flask import request, redirect

@app.route("/goto")
def goto():
    next_url = request.args.get("next")
    return redirect(next_url)  # VULNERABLE: open redirect
