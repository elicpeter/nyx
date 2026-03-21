import os
import shlex
from flask import request

def run_command():
    cmd = request.args.get('cmd')
    safe_cmd = shlex.quote(cmd)
    os.system("echo " + safe_cmd)
