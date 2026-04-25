# py-auth-vuln-001: HTTP handler without `@login_required` reads a
# user-supplied path.  Even with path-traversal narrowing, the auth
# concern stays — `state-unauthed-access` should fire because the
# privileged FILE_IO sink is reached without authentication.
from flask import request

def handle_download():
    name = request.args.get("file")
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        return "denied"
    with open("/var/data/" + name, "r") as f:
        return f.read()
