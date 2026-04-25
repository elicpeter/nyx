import subprocess
from flask import request

def run_command():
    cmd = request.args.get('cmd')
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    return output
