"""FP GUARD — cross-call-site specialization (int vs string branches).

`send` is called in two branches.  One branch passes a strongly-typed
int (parsed via int()), the other passes a constant.  Neither call
site can carry a shell-injection payload to the subprocess sink.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import subprocess


def send(arg) -> None:
    subprocess.run(["logger", str(arg)], check=False)


def entry() -> None:
    raw = os.environ.get("COUNT", "0")
    if raw:
        send(int(raw))       # int() → Cap::all sanitiser
    else:
        send("anon")         # constant
