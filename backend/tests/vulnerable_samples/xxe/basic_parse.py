"""CWE-611: XML External Entity — user-uploaded XML parsed without disabling external entities"""
import xml.etree.ElementTree as ET
from flask import request

@app.route("/parse", methods=["POST"])
def parse_xml():
    xml_data = request.files["xml"].read()
    tree = ET.parse(xml_data)  # VULNERABLE: XXE if external entities enabled
    return str(tree.getroot().tag)
