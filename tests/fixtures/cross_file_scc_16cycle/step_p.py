import subprocess
from step_a import step_a


def step_p(x):
    # Back-edge closes the 16-node SCC: {step_a, ..., step_p}.
    if x == "recursive":
        step_a(x)
    # Sink at the far end of the cycle.  Requires fifteen backwards
    # cross-file summary updates to reach step_a.
    subprocess.run(x, shell=True)
