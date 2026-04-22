"""Bounded integer from a cross-file callee is used in an interpolated
shell string.

`safe_index()` lives in another file and returns a literal 42.  The
SSA summary's `return_abstract` captures `exact(42)`; CF-3 mirrors it
as a per-parameter Clamped transfer so summary-path resolution
synthesises the bound at the caller.  The SHELL_ESCAPE dual-gate
suppression then fires because every tainted leaf flowing into the
subprocess call is proven Int-typed and bounded.
"""

import subprocess
from helper import safe_index


def run():
    idx = safe_index()
    subprocess.run(["/bin/echo", f"index={idx}"], shell=False)
