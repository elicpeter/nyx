import subprocess
from source import get_user_input

def run_command():
    data = get_user_input()
    subprocess.call(data, shell=True)
