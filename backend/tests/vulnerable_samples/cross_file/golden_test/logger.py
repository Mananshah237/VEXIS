import sqlite3

def log_search(client_id, query):
    db = sqlite3.connect("app.db")
    db.execute(f"INSERT INTO search_log (client_id, query) VALUES ('{client_id}', '{query}')")
