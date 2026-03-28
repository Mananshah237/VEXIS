"""
SSRF via requests.get — CWE-918 CRITICAL
Attacker controls the URL fetched by the server.
"""
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return jsonify({"body": resp.text[:500]})
