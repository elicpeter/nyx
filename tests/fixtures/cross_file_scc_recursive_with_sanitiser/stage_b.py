import subprocess
from stage_a import stage_a


def pass_through(sanitised):
    # Only recurses on the empty string — keeps stage_a/stage_b in one SCC
    # without running the back edge in practice.  The sink is reached only
    # through the sanitised payload.
    if sanitised == "":
        return stage_a(sanitised)
    subprocess.call(sanitised, shell=True)
