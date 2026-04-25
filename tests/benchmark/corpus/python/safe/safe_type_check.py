import sqlite3
from flask import request

def get_user():
    user_id = request.args.get('id')
    if not isinstance(user_id, int):
        return "bad input"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result
