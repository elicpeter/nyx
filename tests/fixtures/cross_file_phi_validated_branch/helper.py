"""Branched helper in a separate file.

The helper has two return paths:
  - validated branch → returns the input unchanged (Identity)
  - raw branch → also returns the input (Identity)

Without Phase CF-4 the SSA summary collapses both paths into a single
union transform — losing the fact that one branch validates and the
other does not.  CF-4 preserves the per-return decomposition so the
caller's path state can map to the validated branch.

This fixture is deliberately shaped so both returns are Identity; what
differs is the *predicate gate* at each return, which CF-4 records.
"""


def maybe_pass(value, validated):
    if validated:
        # Validated path: assumes caller already checked `value`.
        return value
    else:
        # Unvalidated raw path.
        return value
