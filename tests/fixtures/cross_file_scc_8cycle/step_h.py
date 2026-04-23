import subprocess
from step_a import step_a


def step_h(x):
    # Back-edge closes the SCC: {step_a, step_b, ..., step_h}.
    if x == "recursive":
        step_a(x)
    # Sink at the far end of the cycle.  The param-to-sink fact must
    # propagate backwards through seven cross-file summary updates
    # before the caller in server.py sees the transitive flow.
    subprocess.run(x, shell=True)
