"""
Safe SSRF — URL is hardcoded, no user input reaches the HTTP call.
Expected: 0 findings (false positive check).
"""
import requests
from flask import Flask, jsonify

app = Flask(__name__)

# Fixed upstream — not user-controlled
HEALTH_ENDPOINT = "https://internal.api/health"


@app.route("/health")
def health_proxy():
    resp = requests.get(HEALTH_ENDPOINT, timeout=5)
    return jsonify({"status": "ok", "upstream": resp.status_code})
