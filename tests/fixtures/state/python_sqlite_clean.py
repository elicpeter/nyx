import sqlite3

def query_safe():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.close()
