import subprocess
from transform import transform_input

def prepare_and_run(cmd):
    subprocess.call(cmd, shell=True)

def retry_transform(data):
    return transform_input(data)
