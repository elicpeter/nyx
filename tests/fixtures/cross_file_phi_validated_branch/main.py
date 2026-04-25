"""Caller for the validated-branch fixture.

User input flows through a cross-file helper with two return paths, then
into a SQL sink.  The call site is unguarded, so the predicate-
consistent application behaves identically to the aggregate — this
fixture is the baseline structural coverage: the decomposition exists in
the summary and the summary-application path does not crash when
consulted.
"""

import sqlite3
from flask import request
from helper import maybe_pass


def process():
    user_input = request.args.get("q")
    forwarded = maybe_pass(user_input, True)
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE name = '" + forwarded + "'")
