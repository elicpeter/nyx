"""FP GUARD — struct-field isolation (Python class attributes).

The tainted value is stored in `self.user_input`.  The sink reads
`self.default_cmd`, which is set to a hardcoded constant in __init__.
A precise analysis must not treat the class instance as a single
tainted object.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import subprocess


class Runner:
    def __init__(self):
        self.default_cmd = "/usr/bin/uptime"   # hardcoded constant
        self.user_input = ""                   # filled in from taint

    def set_user(self):
        self.user_input = os.environ.get("USER_CMD", "")

    def run(self):
        # only the default attribute is passed to subprocess
        subprocess.run([self.default_cmd], check=False)
