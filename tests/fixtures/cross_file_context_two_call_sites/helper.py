"""Helper defined in a separate file. Its body forwards its argument
to subprocess.call — a CMD_EXEC sink."""

import subprocess


def run_cmd(cmd):
    subprocess.call(cmd, shell=True)
