"""
CVE-2023-47890 — Path Traversal via bypass-able sanitizer in pyLoad
Source: https://github.com/pyload/pyload/security/advisories/GHSA-h73m-pcfw-25h2
        https://nvd.nist.gov/vuln/detail/CVE-2023-47890
        Vulnerable commit: df094db67ec6e25294a9ac0ddb4375fd7fb9ba00

Affected: pyload-ng < 0.5.0b3.dev75
Vuln class: CWE-22 (Path Traversal)
Severity: HIGH

Description:
  The /json/edit_package Flask endpoint extracts pack_folder from request.form
  and applies only a single-pass replace("../", "") sanitizer, which is bypassable
  by doubling the traversal sequence: "....//....//etc" becomes "../../../etc"
  after the single-pass strip. Allows writing downloaded files to arbitrary paths.

  Original vulnerable code (src/pyload/webui/app/blueprints/json_blueprint.py, commit df094db):
    @bp.route("/edit_package", methods=["POST"])
    @login_required
    def edit_package():
        pack_id = int(flask.request.form["pack_id"])
        pack_folder = (
            flask.request.form["pack_folder"]
                 .lstrip(f"{os.path.sep}")
                 .replace(f"..{os.path.sep}", "")  # <-- single-pass, bypassable
        )
        data = {
            "name":     flask.request.form["pack_name"],
            "_folder":  pack_folder,               # tainted value stored
            "password": flask.request.form["pack_pws"],
        }
        api.set_package_data(pack_id, data)         # writes files to pack_folder

  Exploit payload:
    POST pack_folder=....//....//....//config/scripts/download_finished/
    Single-pass replace turns "....//": removes "../" → leaves "../"
    Resolved path escapes /downloads/ → RCE when next download completes.
"""
import os
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
BASE_DIR = '/var/pyload/downloads'


@app.route('/json/edit_package', methods=['POST'])
def edit_package():
    pack_id = request.form.get('pack_id', '')
    pack_name = request.form.get('pack_name', '')

    # CVE-2023-47890: single-pass replace is bypassable
    # "....//etc/passwd" → replace("../","") → "../etc/passwd" → path escape!
    pack_folder = (
        request.form.get('pack_folder', '')
               .lstrip(os.path.sep)
               .replace(f"..{os.path.sep}", "")   # PARTIAL SANITIZER — bypassable
    )

    # Vulnerable: pack_folder used directly in filesystem operation
    full_path = os.path.join(BASE_DIR, pack_folder)
    # Simulate writing a file to the resolved path
    try:
        os.makedirs(full_path, exist_ok=True)
        return jsonify({'status': 'ok', 'path': full_path, 'name': pack_name, 'id': pack_id})
    except OSError as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download')
def download_file():
    # Second vulnerable endpoint: direct path from request.args
    filename = request.args.get('file', '')
    file_path = os.path.join(BASE_DIR, filename)
    return send_file(file_path)
