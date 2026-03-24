import sqlite3

def query_unsafe():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER)")
    # conn never closed — leak
