"""Points-to alias fixture: helper that mutates its first argument by
storing its second argument into a field.

The helper returns None, so nothing propagates through the return.
Without a points-to channel the cross-file summary loses the taint
edge entirely.  With it, the analysis emits `Param(1) -> Param(0)`
and the caller's argument alias inherits the stored taint.
"""


def populate(target, user_input):
    target.data = user_input
