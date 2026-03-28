import sqlite3
import psycopg2
from flask import request

# sqlite3 with ? placeholder
def get_user_sqlite():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# psycopg2 with %s placeholder
def get_user_pg():
    name = request.args.get("name")
    conn = psycopg2.connect("dbname=app")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cursor.fetchone()

# executemany with ? placeholder
def bulk_insert():
    items = request.json.get("items")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO items (name) VALUES (?)", items)
    conn.commit()

# conn.execute with ? placeholder
def get_user_conn():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
