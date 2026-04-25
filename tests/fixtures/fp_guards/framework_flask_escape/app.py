"""FP GUARD — framework-safe pattern (Flask route + html.escape).

A Flask route reads a tainted query parameter and renders it via
``make_response`` after passing through ``html.escape`` — a recognised
HTML_ESCAPE sanitiser in the stdlib.  The framework response helper
is an XSS sink only for *unescaped* data; Nyx must respect the
sanitiser cap.

Expected: NO taint-unsanitised-flow finding.
"""
import html

from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")   # tainted query value
    safe = html.escape(name)              # HTML_ESCAPE sanitiser
    return make_response("<p>Hello, " + safe + "</p>")
