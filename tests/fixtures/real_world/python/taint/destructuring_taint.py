import os
import subprocess

cmd = os.getenv("CMD")
arg = os.getenv("ARG")
subprocess.run(arg, shell=True)
