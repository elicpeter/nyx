"""FP GUARD — type-driven suppression (int parsed from request used in SQL).

Tainted query-string value is parsed with int() before being
interpolated into a SQL string.  The value is structurally guaranteed
to be a decimal integer — no SQL-injection surface.

Expected: NO taint-unsanitised-flow finding.
"""
import sqlite3


def lookup(request, conn: sqlite3.Connection):
    raw = request.args["id"]               # tainted web source
    uid = int(raw)                         # int() sanitiser
    cur = conn.execute("SELECT name FROM users WHERE id = " + str(uid))
    return cur.fetchone()
