import os
import subprocess

from shell_utils import safe_shell_arg


def handle():
    """SAFE: the tainted env variable is passed through shlex.quote before
    reaching subprocess.call.

    The sanitiser is defined in a separate file (shell_utils.py) to exercise
    cross-file sanitiser propagation.  shlex.quote covers SHELL_ESCAPE so
    no taint-unsanitised-flow should be reported here.
    """
    user_dir = os.getenv("TARGET_DIR")    # taint source
    safe = safe_shell_arg(user_dir)       # cross-file SHELL_ESCAPE sanitiser
    subprocess.call(["ls", "-la", safe])  # sanitised value reaches shell arg
