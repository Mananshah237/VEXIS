"""Vulnerable: OS command injection via os.system"""
from flask import request
import os


def ping_host():
    host = request.args.get("host", "localhost")
    # VULNERABLE: user input in shell command
    result = os.system(f"ping -c 1 {host}")
    return {"exit_code": result}
