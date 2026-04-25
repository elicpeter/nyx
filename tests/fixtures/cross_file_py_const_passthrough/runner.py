import subprocess

from constants import get_safe_command


def run_diagnostic():
    """SAFE: the command comes from a module-level constant in constants.py.

    There is no taint source anywhere in the call chain.  The subprocess.call
    invocation uses only the hardcoded string returned by get_safe_command(),
    so no vulnerability should be reported.
    """
    cmd = get_safe_command()          # returns a string literal — no taint
    subprocess.call(cmd, shell=True)  # constant arg → no finding expected
