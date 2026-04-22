"""FP GUARD — sanitizer edge case (multi-step chain).

Value is stripped then shell-escaped before reaching subprocess.run.
The last sanitiser (shlex.quote) covers the shell context; the engine
must not get confused by the trim-first, escape-second pattern.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import shlex
import subprocess


def run():
    raw = os.environ.get("ARG", "")
    trimmed = raw.strip()                 # transform; still tainted
    safe = shlex.quote(trimmed)           # final SHELL_ESCAPE sanitiser
    subprocess.run(["echo", safe], check=False)
