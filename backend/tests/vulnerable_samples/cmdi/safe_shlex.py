"""Safe: Command with shlex.quote — should NOT be flagged as injectable"""
from flask import request
import subprocess
import shlex


def run_analysis():
    filename = request.args.get("file", "")
    # SAFE: shlex.quote prevents command injection
    safe_filename = shlex.quote(filename)
    result = subprocess.run(
        ["analyze_tool", safe_filename],
        capture_output=True,
        text=True,
    )
    return {"output": result.stdout}
