import os

def run():
    cmd = os.getenv("CMD")
    cmd = cmd + " -safe"
    os.system(cmd)
