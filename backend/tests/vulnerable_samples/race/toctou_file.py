"""CWE-362: TOCTOU race condition — check then act without atomic locking"""
import os
from flask import request

@app.route("/delete")
def delete_file():
    path = request.args.get("file")
    if os.path.exists(path):  # CHECK
        os.remove(path)  # ACT — race window between check and act
    return "Done"
