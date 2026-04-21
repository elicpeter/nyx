"""Phase 2b.2 — targeted validation of first argument.

`validate(x, 100)` — `x` is a plain identifier in the first position.
`classify_condition_with_target` extracts `"x"` as the validation target, so
on the true branch `x` is marked validated and the sink on `x` does not fire.

Regression guard: if target extraction breaks for single-identifier first
args, this fixture would produce a false positive.
"""

import os
from flask import request


def validate(value, max_len):
    return isinstance(value, str) and len(value) <= max_len


def handle():
    x = request.args.get("q")  # tainted (Cap::all)
    if validate(x, 100):
        os.system(x)  # SAFE — x is validated on this branch
