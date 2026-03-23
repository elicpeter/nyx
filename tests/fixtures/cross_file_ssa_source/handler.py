import subprocess
from reader import read_input

def handle():
    data = read_input()
    subprocess.call(data, shell=True)
