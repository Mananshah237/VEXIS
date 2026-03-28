"""
Vulnerable sample: OS Command Injection via subprocess with shell=True.
CWE-78 — Improper Neutralization of Special Elements used in an OS Command.

Expected: VEXIS finds CMDi at subprocess.run() with source at request.args.get("host")
"""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # VULNERABLE: shell=True with user-controlled input
    # Attacker can inject: ; cat /etc/passwd or $(whoami)
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    # VULNERABLE: subprocess.call with shell=True
    subprocess.call("nslookup " + domain, shell=True)
    return "done"
