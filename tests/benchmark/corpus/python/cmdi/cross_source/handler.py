import subprocess
from reader import read_input

data = read_input()
subprocess.call(data, shell=True)
