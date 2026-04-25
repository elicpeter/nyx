import os
import sqlite3

def get_user():
    user_id = os.environ.get("USER_ID")
    conn = sqlite3.connect("app.db")
    result = conn.execute("SELECT * FROM users WHERE id = " + user_id)
    return result.fetchall()
