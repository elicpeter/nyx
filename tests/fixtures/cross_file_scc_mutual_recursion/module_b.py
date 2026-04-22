from module_a import step_a, run_shell


def step_b(data):
    # Recurses into step_a for even-length payloads; sinks directly
    # otherwise.  The base case (run_shell) is the sink that must
    # surface to the caller in server.py across the SCC fixed-point.
    if len(data) % 2 == 0:
        return step_a(data)
    run_shell(data)
    return data
