import shlex
from stage_b import pass_through


def stage_a(payload):
    # Cycle edge that sanitises before recursing into stage_b.  The
    # mutual recursion is real (summaries need joint convergence) but
    # every cross-file flow passes through shlex.quote, so the summary
    # should record sanitizer_caps(SHELL_ESCAPE) on the parameter and
    # prevent the downstream CMDI finding at the caller.
    safe = shlex.quote(payload)
    return pass_through(safe)
