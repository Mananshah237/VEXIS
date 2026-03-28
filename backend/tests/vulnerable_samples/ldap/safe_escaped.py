"""CWE-90 Safe: LDAP filter chars escaped"""
import ldap
import ldap.filter
from flask import request

@app.route("/search")
def search():
    username = request.args.get("username")
    safe_user = ldap.filter.escape_filter_chars(username)
    conn = ldap.initialize("ldap://localhost")
    results = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        f"(uid={safe_user})",  # SAFE: filter chars escaped
    )
    return str(results)
