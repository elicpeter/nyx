import os
from module_a import step_a


def handler():
    user_cmd = os.environ["USER_CMD"]
    # Taint must travel: env source → step_a → step_b → run_shell sink
    # across a 2-file SCC.  Without joint fixed-point iteration the
    # cross-file summary for step_a/step_b is sub-converged on the first
    # pass and the transitive CMDI disappears from this call site.
    step_a(user_cmd)
