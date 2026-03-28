from rate_limiter import check_rate_limit
from logger import log_search
import sqlite3

def search(request):
    check_rate_limit(request)
    query = request.query_params.get("q", "")
    safe_query = query.replace("'", "''").replace(";", "")
    log_search(request.state.client_id, safe_query)
    db = sqlite3.connect("app.db")
    results = db.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{safe_query}%",))
    return results
