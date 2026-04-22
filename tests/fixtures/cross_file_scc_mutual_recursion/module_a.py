from module_b import step_b


def step_a(payload):
    # Mutually recursive with module_b.step_b — the SCC spans two files.
    # On the first iteration step_a's summary has no param_to_sink flag
    # because step_b has not yet been summarised; the SCC fixed-point
    # loop refines both summaries across iterations until the transitive
    # taint is visible at the caller in server.py.
    return step_b(payload)


def run_shell(cmd):
    import subprocess
    subprocess.call(cmd, shell=True)
