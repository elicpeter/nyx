# Nyx benchmark synthetic — negative (safe) fixture.
#
# Pins the CVE-2022-24776 (Flask-AppBuilder) guarded-passthrough open-redirect
# confiner: `get_safe_redirect(url)` returns its URL parameter only on the
# validated branch of a URL-safety guard (`is_safe_redirect_url`, a same-origin
# `netloc` check), so `redirect(get_safe_redirect(next_url))` — where the
# wrapper collapses out of the SSA and the tainted URL reaches the sink
# directly — must NOT fire taint-open-redirect / cfg-unguarded-sink.

from urllib.parse import urljoin, urlparse

from flask import Flask, redirect, request

app = Flask(__name__)


def is_safe_redirect_url(url):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, url))
    return (
        redirect_url.scheme in ("http", "https")
        and host_url.netloc == redirect_url.netloc
    )


def get_safe_redirect(url):
    if url and is_safe_redirect_url(url):
        return url
    return "/"


@app.route("/login")
def login():
    next_url = request.args.get("next", "")
    return redirect(get_safe_redirect(next_url))
