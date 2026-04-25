"""Wrong-argument validation must not validate taint.

`validate(limit, x)` — the validator takes `limit` (the bound) as its
first argument.  `classify_condition_with_target` extracts `"limit"` as
the validation target, so on the true branch only `limit` is marked
validated — NOT `x`.  The tainted `x` flows to the sink and the finding
must fire.

Regression guard: if the `Some(target)` branch ever regressed to marking
all condition vars as validated, the tainted `x` would be silently
dropped.
"""

import os
from flask import request


def validate(limit, value):
    return isinstance(value, str) and len(value) <= limit


def handle():
    x = request.args.get("q")  # tainted (Cap::all)
    limit = 100
    if validate(limit, x):
        os.system(x)  # VULN — `limit` was validated, not `x`
