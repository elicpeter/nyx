# Synthetic regression guard for CVE-2024-32651 (changedetection.io) Layer G.
# A Jinja2 *sandboxed* environment neutralises template injection: rendering
# untrusted input through `ImmutableSandboxedEnvironment(...).from_string(...)`
# must NOT fire `py.xss.jinja_from_string` (the sandbox blocks the
# attribute-traversal RCE payloads).  Pairs with
# xss/ssti_unrestricted_from_string.py (the unrestricted-Environment positive).
import jinja2.sandbox
from flask import request


def render_notification():
    body = request.form.get('notification_body')
    env = jinja2.sandbox.ImmutableSandboxedEnvironment(extensions=[])
    return env.from_string(body).render({})
