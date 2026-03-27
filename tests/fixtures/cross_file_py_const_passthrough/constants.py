"""Constant definitions module.

All values exported from this module are compile-time constants — none of
them originate from environment variables, user input, or any other taint
source.  Any function that returns these values propagates no taint.
"""

ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "date"]
DEFAULT_REPORT_CMD = "du -sh /var/log"


def get_safe_command():
    """Returns a hardcoded diagnostic command string.

    No taint source: the return value is a string literal.
    """
    return DEFAULT_REPORT_CMD
