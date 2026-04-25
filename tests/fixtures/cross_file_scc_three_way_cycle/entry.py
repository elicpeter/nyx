import os
from node_a import forward_a


def handler():
    cmd = os.environ["USER_CMD"]
    # Flow: env source -> forward_a -> forward_b -> forward_c (sink).
    # The 3-file SCC has to converge before `forward_a`'s summary
    # reflects the downstream CMDI.
    forward_a(cmd)
