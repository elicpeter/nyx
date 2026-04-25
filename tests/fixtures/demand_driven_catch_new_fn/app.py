"""demand_driven_catch_new_fn.

Documents the aspirational catch case: a deep chain where forward
analysis loses precision because a summary cap squashes the flow, but
backwards could still reach a user source.

In the current backwards driver, walks terminate at [`SsaOp::Param`]
boundaries rather than traversing reverse call graph edges; so this
fixture asserts the conservative behaviour (forward still fires the
finding when the caller is in the same file; nothing is added or
removed).  A follow-up can flip the fixture once reverse-edge
expansion lands.
"""

import sqlite3
from flask import request


def passthrough(x):
    return x


def handle():
    user_input = request.args.get("q")
    piped = passthrough(user_input)
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE name = '" + piped + "'")
