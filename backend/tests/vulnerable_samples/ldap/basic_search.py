"""CWE-90: LDAP injection — user input in LDAP filter without escaping"""
import ldap
from flask import request

@app.route("/search")
def search():
    username = request.args.get("username")
    conn = ldap.initialize("ldap://localhost")
    results = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        f"(uid={username})",  # VULNERABLE: LDAP injection
    )
    return str(results)
