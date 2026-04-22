"""Two call sites to the same cross-file helper.

Without CF-2, both calls go through the conservative `run_cmd` summary
and the suite may report noise on the constant-string call.  With CF-2,
the constant-string call is context-sensitively specialised and sees
clean input, while the tainted call produces the expected finding.
"""

import os

from helper import run_cmd


def handle(event):
    # TAINTED: os.environ is a taint source; flows through run_cmd to subprocess.call.
    user_cmd = os.environ.get("USER_CMD", "")
    run_cmd(user_cmd)

    # SAFE: constant literal — no real vulnerability.
    run_cmd("ls -la")
