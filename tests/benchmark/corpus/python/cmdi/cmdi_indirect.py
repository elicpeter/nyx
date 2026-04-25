import subprocess
from flask import request

def ping_host():
    host = request.args.get('host')
    cmd = "ping -c 1 " + host
    subprocess.run(cmd, shell=True)
