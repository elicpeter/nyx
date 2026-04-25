import os


class JobRequest:
    """Data-transfer object populated from environment variables.

    The `cmd` attribute is a taint source: os.environ["JOB_CMD"] is
    user-controlled at deployment time / via process substitution.
    """

    def __init__(self):
        self.cmd = os.environ.get("JOB_CMD")  # taint flows into object attribute
        self.label = os.environ.get("JOB_LABEL", "unnamed")
