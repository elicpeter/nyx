import os
import subprocess

def process_input(cmd, label):
    """Only param 0 (cmd) flows to CMD sink; param 1 (label) is safe."""
    subprocess.call(cmd, shell=True)
    print(label)
