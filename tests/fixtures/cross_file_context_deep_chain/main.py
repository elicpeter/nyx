"""File A — entry point of the A → B → C chain.

Taints flow from os.environ through middle.forward (File B) into
sinks.exec_cmd (File C).  With k=1 context sensitivity, the B-level
specialisation applies but B→C inline is depth-capped so it resolves
via summary.  The finding must still surface end-to-end.
"""

import os

from middle import forward


def handle():
    user_cmd = os.environ.get("USER_CMD", "")
    forward(user_cmd)
