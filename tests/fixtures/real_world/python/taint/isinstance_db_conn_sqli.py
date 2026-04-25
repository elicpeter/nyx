import sqlite3
from flask import request

def query_with_guard(conn):
    user_id = request.args.get('id')
    if isinstance(conn, sqlite3.Connection):
        conn.execute("SELECT * FROM users WHERE id = " + user_id)
