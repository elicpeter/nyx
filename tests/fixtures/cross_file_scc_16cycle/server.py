from flask import request
from step_a import step_a


def handler():
    user_cmd = request.args.get("cmd")
    # Taint enters the 16-function SCC at step_a; needs sixteen SCC
    # fix-point iterations to propagate back into step_a's summary.
    step_a(user_cmd)
