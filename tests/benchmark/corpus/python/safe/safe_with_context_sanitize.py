# py-context-sanitize-001: Python `with`-context resource pattern
# around a privileged file sink.  The user-supplied path is sanitised
# (path-traversal rejection) and the handler is wrapped in
# `@login_required`, so neither taint nor auth findings should fire on
# the sink — `with`-context resource management does not re-introduce
# taint that the sanitiser already cleared.
from flask import request
from flask_login import login_required

@login_required
def handle_log():
    raw = request.args.get("file")
    if ".." in raw or raw.startswith("/") or raw.startswith("\\"):
        return "denied"
    with open("/var/log/" + raw, "r") as f:
        return f.read()
