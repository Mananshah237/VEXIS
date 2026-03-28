"""CWE-611 Safe: uses defusedxml which disables external entity processing"""
import defusedxml.ElementTree as ET
from flask import request

@app.route("/parse", methods=["POST"])
def parse_xml():
    xml_data = request.files["xml"].read()
    tree = defusedxml.parse(xml_data)  # SAFE: defusedxml prevents XXE
    return str(tree.getroot().tag)
