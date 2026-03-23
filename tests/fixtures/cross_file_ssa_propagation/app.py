import os
import subprocess
from wrapper import process

def run():
    data = os.environ["INPUT"]
    result = process(data)
    subprocess.call(result, shell=True)
