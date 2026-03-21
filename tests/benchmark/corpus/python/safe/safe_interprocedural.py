import os
import shlex
from flask import request

def sanitize(s):
    return shlex.quote(s)

def run_command():
    cmd = request.args.get('cmd')
    os.system(sanitize(cmd))
