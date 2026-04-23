# Regression fixture: a nested def captures a tainted variable from
# its enclosing function and sinks it via subprocess.run(..., shell=True).
#
# The engine must follow the closure boundary — i.e. recognise that
# `handler` references `tainted` from `make_handler` — and surface a
# taint-unsanitised-flow finding from env to subprocess.
import os
import subprocess


def make_handler():
    tainted = os.environ["USER_INPUT"]

    def handler(req):
        subprocess.run(tainted, shell=True)

    return handler


h = make_handler()
h({})
