"""FP GUARD — sanitizer edge case (shell escape with special chars).

Tainted environment value passes through shlex.quote before reaching
subprocess.run.  Even when the raw value contains metacharacters
(`; rm -rf /`, backticks, quotes), shlex.quote produces a safely
single-quoted token — subprocess.run with a list argv never re-shells
it.  Nyx's SHELL_ESCAPE cap must cover shlex.quote.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import shlex
import subprocess


def run_ls():
    raw = os.environ.get("DIR", "")  # tainted source
    quoted = shlex.quote(raw)         # SHELL_ESCAPE sanitiser
    subprocess.run(["ls", "-la", quoted], check=False)
