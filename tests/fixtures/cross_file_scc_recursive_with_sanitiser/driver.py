import os
from stage_a import stage_a


def handler():
    cmd = os.environ["USER_CMD"]
    # Every cross-file flow through the SCC is sanitised by shlex.quote
    # in stage_a.  With joint fixed-point convergence, stage_a's summary
    # records a SHELL_ESCAPE sanitizer on its parameter and the CMDI
    # finding at the caller should be suppressed.
    stage_a(cmd)
