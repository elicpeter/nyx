import os
import sqlite3

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()


def handle():
    x = input()
    os.system(x); cursor.execute(x)
