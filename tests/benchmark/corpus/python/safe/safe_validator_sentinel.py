# py-validator-sentinel-001: cross-function validator that returns an
# empty string sentinel on rejection rather than a bool, with a string
# guard on the sentinel before the privileged sink.  The handler is
# wrapped in `@login_required` so neither `taint-unsanitised-flow` (path
# narrowing through the validator) nor `state-unauthed-access` /
# `cfg-auth-gap` (decorator-level auth) fires.
from flask import request
from flask_login import login_required

def sanitize_path(s):
    if ".." in s or s.startswith("/") or s.startswith("\\"):
        return ""
    return s

@login_required
def handle_download():
    raw = request.args.get("file")
    safe = sanitize_path(raw)
    if safe == "":
        return "denied"
    with open("/var/data/" + safe, "r") as f:
        return f.read()
