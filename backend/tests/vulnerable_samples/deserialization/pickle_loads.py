"""
Insecure deserialization via pickle.loads — CWE-502 CRITICAL
Attacker-controlled bytes deserialized with pickle allows arbitrary code execution.
"""
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load_object():
    data = request.args.get("data")
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)
