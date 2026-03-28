"""
Safe deserialization — uses yaml.safe_load instead of yaml.load.
Expected: 0 findings (false positive check).
"""
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/parse")
def parse_config():
    body = request.data.decode("utf-8")
    config = yaml.safe_load(body)
    return jsonify(config)
