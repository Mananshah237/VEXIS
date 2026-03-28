"""
Vulnerable: eval() with unsanitized user input — arbitrary Python code execution.
Expected: 1 finding, CWE-78 (command injection / code execution), CRITICAL.
"""
from flask import request


@app.route("/calc")
def calculator():
    # VULNERABLE: eval with user input = arbitrary code execution
    # Payload: __import__('os').system('id')
    expr = request.form.get("expr", "")
    result = eval(expr)
    return str(result)
