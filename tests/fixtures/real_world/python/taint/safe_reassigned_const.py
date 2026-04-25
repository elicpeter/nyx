import os

def run():
    cmd = os.getenv("CMD")
    cmd = "echo safe"
    os.system(cmd)
