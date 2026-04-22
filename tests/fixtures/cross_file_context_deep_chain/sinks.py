"""File C — contains the terminal CMD_EXEC sink."""

import subprocess


def exec_cmd(cmd):
    subprocess.call(cmd, shell=True)
