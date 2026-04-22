"""Points-to alias caller: reads a tainted environment variable,
passes it to a cross-file void helper that stores the value into the
first argument's field, then reads the mutated field back out and
runs it as a shell command.
"""

import os
import subprocess

from helper import populate


class Target:
    def __init__(self):
        self.data = ""


def run():
    user_input = os.environ.get("USER_CMD")
    t = Target()
    populate(t, user_input)
    subprocess.call(t.data, shell=True)  # VULN: tainted field -> shell sink
