"""FP GUARD — cross-call-site specialization (Python: sanitized caller).

`run_shell` is a shell-exec helper.  Only one call-site reaches it in
this fixture, and that call-site passes a shlex.quote-sanitised
value.  The inline-analysis cache key depends on the sanitised cap
bits, so the internal subprocess call must not surface as an
unsanitised flow.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import shlex
import subprocess


def run_shell(token: str) -> None:
    subprocess.run(["sh", "-c", "echo " + token], check=False)


def entry() -> None:
    raw = os.environ.get("LABEL", "")
    safe = shlex.quote(raw)           # SHELL_ESCAPE sanitiser
    run_shell(safe)                   # sanitised arg flows through
