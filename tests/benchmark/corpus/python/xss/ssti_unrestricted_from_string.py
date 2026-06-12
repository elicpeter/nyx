# Synthetic positive for CVE-2024-32651 (changedetection.io) Layer G.
# An *unrestricted* Jinja2 environment renders untrusted input via
# `Environment(loader=BaseLoader).from_string(...)` — a server-side template
# injection sink that must fire `py.xss.jinja_from_string`.  Pairs with
# safe/safe_jinja_sandboxed_from_string.py (the sandboxed negative): the only
# difference is the environment class, which is exactly what Layer G keys on.
from flask import request
from jinja2 import Environment, BaseLoader


def render_notification():
    body = request.form.get('notification_body')
    env = Environment(loader=BaseLoader)
    return env.from_string(body).render()
