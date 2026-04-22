"""demand_driven_prove_infeasible.

Forward taint flows through a branch that subsequent constraint analysis
demonstrates is infeasible on the sink path.  Backwards analysis walks
from the sink and accumulates the branch polarity; the current
backwards pass does not yet invoke the SMT solver on the accumulated
path, so the fixture asserts the structural finding *still* fires (i.e.
the backwards pass does not regress forward behaviour) and that
`backwards-confirmed` is emitted when the backwards walk does reach
the user source.

A follow-up can flip this fixture's `forbidden_findings` once the
path-constraint integration lands.
"""

import sqlite3
from flask import request


def handle():
    user_input = request.args.get("q")
    # Structural forward finding still fires; the backwards pass
    # confirms it rather than pruning it.
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE name = '" + user_input + "'")
