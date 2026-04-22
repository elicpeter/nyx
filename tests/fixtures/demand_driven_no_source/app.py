"""demand_driven_no_source.

A SQL sink whose payload is a literal constant with no tainted flow.
Forward produces no finding; backwards would also produce none (there
is no sink value with tainted operands to walk from).  The fixture
guards against a regression where enabling backwards accidentally
emits a standalone finding with no upstream source.
"""

import sqlite3


def handle():
    safe_value = "literal"
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM items WHERE name = '" + safe_value + "'")
