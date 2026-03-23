import os
import subprocess

def handle():
    cmd = os.environ.get("CMD")
    if cmd is None:
        if cmd == "rm -rf":
            # Infeasible: cmd is None AND cmd == "rm -rf"
            subprocess.call(cmd, shell=True)
    subprocess.call(cmd, shell=True)
