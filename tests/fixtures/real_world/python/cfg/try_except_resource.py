import sqlite3

def query_db(path, sql):
    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        results = cursor.fetchall()
        return results
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def query_db_leak(path, sql):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute(sql)
    results = cursor.fetchall()
    return results
    # conn never closed
