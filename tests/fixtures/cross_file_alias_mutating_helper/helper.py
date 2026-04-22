"""Phase CF-6 fixture: helper that mutates its first argument by
storing its second argument into a field.

The helper returns None, so nothing propagates through the return.
Without CF-6 the cross-file summary loses the taint edge entirely.
With CF-6, the analysis emits `Param(1) -> Param(0)` and the caller's
argument alias inherits the stored taint.
"""


def populate(target, user_input):
    target.data = user_input
