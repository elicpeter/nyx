import subprocess

from models import JobRequest


def dispatch():
    """SINK: subprocess.call with shell=True.

    The command originates from JobRequest.cmd (an os.environ value) that was
    set in models.py.  The tainted attribute crosses the file boundary via the
    object reference and reaches the shell execution sink without sanitisation.

    VULN: object-field taint propagation from models.py into handler.py.
    """
    req = JobRequest()
    subprocess.call(req.cmd, shell=True)  # taint from req.cmd → shell sink
