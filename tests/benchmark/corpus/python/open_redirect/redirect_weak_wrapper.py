# Nyx benchmark synthetic — positive (open-redirect) recall guard.
#
# Precision guard for the CVE-2022-24776 guarded-passthrough confiner: a
# redirect wrapped by a helper that does NOT validate the URL host/scheme (a
# plain string transform) must STILL fire taint-open-redirect.  `normalize`
# only trims whitespace, so it is not a recognised open-redirect confiner and
# the attacker-controlled `next` still drives an off-host redirect.

from flask import Flask, redirect, request

app = Flask(__name__)


def normalize(url):
    return url.strip()


@app.route("/login")
def login():
    next_url = request.args.get("next", "")
    return redirect(normalize(next_url))
