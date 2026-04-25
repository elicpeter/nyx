"""demand_driven_reach_source.

A classic source-to-sink flow that the forward engine already detects.
With `backwards_analysis = true`, the post-pass should walk backwards from
the SQL sink, reach the `request.args.get` source, and annotate the
finding with `backwards-confirmed`.

When backwards is OFF (the default), the forward finding still fires with
no annotation — the fixture therefore validates the behaviour is
*strictly additive*.
"""

import sqlite3
from flask import request


def handle():
    user_input = request.args.get("q")
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE name = '" + user_input + "'")
