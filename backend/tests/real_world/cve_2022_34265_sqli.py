"""
CVE-2022-34265 — SQL Injection via Trunc/Extract kind parameter in Django
Source: https://github.com/advisories/GHSA-p64x-8rxx-wf6q
        https://nvd.nist.gov/vuln/detail/CVE-2022-34265
        Confirmed PoC: https://github.com/vulhub/vulhub/tree/master/django/CVE-2022-34265

Affected: Django 3.2.x < 3.2.14, 4.0.x < 4.0.6
Vuln class: CWE-89 (SQL Injection)
Severity: CRITICAL

Description:
  Django's Trunc() and Extract() ORM functions pass the kind/lookup_name argument
  directly into raw SQL without validation. If an application passes a user-controlled
  request parameter to either function, an attacker can inject arbitrary SQL.

  Original vulnerable view (from vulhub/vulhub CVE-2022-34265/vuln/views.py):
    def vul(request):
        date = request.GET.get('date', 'minute')  # untrusted input
        objects = list(
            WebLog.objects
                  .annotate(time=Trunc('created_time', date))  # 'date' injected here
                  .values('time').order_by('-time').annotate(count=Count('id'))
        )
        return JsonResponse(data=objects, safe=False)

  Exploit: GET /?date=minute'%20FROM%20start_datetime))%20OR%201=1;SELECT%20PG_SLEEP(5)--

Flask adaptation (demonstrates same CWE-89 pattern with VEXIS-detectable sources/sinks):
  Uses request.args.get() + raw cursor.execute() to replicate the injection.
  The 'date_trunc' parameter flows directly into an f-string SQL query without validation.
"""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = 'app.db'


@app.route('/analytics')
def analytics():
    # CVE-2022-34265: user controls the date truncation unit — same injection class
    # Original used Django Trunc('created_time', date); here we show the equivalent raw SQL pattern
    date_trunc = request.args.get('date', 'minute')

    conn = sqlite3.connect(DB_PATH)
    # Vulnerable: date_trunc flows directly into f-string SQL without validation
    # Payload: ?date=minute' FROM created_time)) OR 1=1; SELECT * FROM users--
    rows = conn.execute(
        f"SELECT strftime('%{date_trunc}', created_time), COUNT(*) "
        f"FROM weblogs GROUP BY strftime('%{date_trunc}', created_time) ORDER BY 1 DESC"
    ).fetchall()
    conn.close()
    return jsonify({'results': [{'time': r[0], 'count': r[1]} for r in rows]})


@app.route('/api/logs')
def get_logs():
    # Second vulnerable endpoint: group_by column name injection (same CVE class)
    group_by = request.args.get('group_by', 'path')
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(f"SELECT {group_by}, COUNT(*) FROM access_log GROUP BY {group_by}").fetchall()
    conn.close()
    return jsonify({'logs': rows})
