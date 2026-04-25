"""FP GUARD — struct-field isolation (Python dict keys).

Separate dict keys hold separate values.  `data["user"]` receives
taint from the environment; `data["template"]` is a constant.  The
subprocess sink reads only the constant key.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import subprocess


def render():
    data = {
        "user": os.environ.get("NAME", ""),     # taint here
        "template": "/usr/bin/true",            # constant here
    }
    subprocess.run([data["template"]], check=False)
