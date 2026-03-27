import shlex


def safe_shell_arg(arg):
    """Returns a shell-safe version of `arg` using shlex.quote.

    This is a SHELL_ESCAPE sanitiser.  Any tainted value passed through
    this helper is neutralised for shell execution contexts.
    """
    return shlex.quote(arg)
