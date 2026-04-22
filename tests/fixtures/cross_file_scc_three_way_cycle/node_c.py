from node_a import forward_a


def forward_c(payload):
    # Base case — sinks the payload.  `subprocess.call(..., shell=True)`
    # is the CMDI sink.  Must still report a finding at the caller in
    # entry.py even though the flow traverses 3 cross-file summary edges.
    import subprocess
    if len(payload) == 0:
        # Dead branch — keeps the SCC alive so forward_c is on the cycle
        # and not a leaf.
        return forward_a(payload)
    subprocess.call(payload, shell=True)
