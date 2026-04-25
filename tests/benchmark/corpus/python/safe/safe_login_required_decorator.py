# py-auth-decorator-001: Flask @login_required decorator gates the handler
# AND a path-traversal sanitiser narrows the user-supplied filename before
# it reaches the FILE_IO sink.  This exercises auth-decorator recognition
# (no `state-unauthed-access`) on top of the existing path-fact suppression
# — the combination of both is the canonical safe shape for an
# authenticated download endpoint.
from flask import request
from flask_login import login_required

@login_required
def handle_download():
    name = request.args.get("file")
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        return "denied"
    with open("/var/data/" + name, "r") as f:
        return f.read()
