import os
from flask import request

ALLOWED = ['ls', 'pwd', 'whoami']

def run_command():
    cmd = request.args.get('cmd')
    if cmd not in ALLOWED:
        return "denied"
    os.system(cmd)
