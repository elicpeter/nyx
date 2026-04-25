# py-validator-sentinel-vuln-001: same shape as
# safe_validator_sentinel.py but the rejection sentinel is checked with
# the WRONG comparator (`!=` instead of `==`), so the rejection branch
# is the one that reaches the sink.  `taint-unsanitised-flow` should
# fire on the SQL sink because the validated path is bypassed.
from flask import request
from flask_login import login_required
import sqlite3

def sanitize_id(s):
    if not s.isdigit():
        return ""
    return s

@login_required
def handle_lookup():
    raw = request.args.get("id")
    safe = sanitize_id(raw)
    # Buggy: condition negated — we run the query when sanitisation REJECTED.
    if safe != "":
        conn = sqlite3.connect("app.db")
        conn.execute("SELECT * FROM users WHERE name = '" + raw + "'")
