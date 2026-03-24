import os
from flask import request

ALLOWED_CMDS = ['status', 'version', 'uptime']

def run():
    cmd = request.args.get('cmd')
    if cmd not in ALLOWED_CMDS:
        return 'forbidden', 403
    os.system(cmd)
