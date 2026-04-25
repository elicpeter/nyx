import os
from flask import request

def run_command():
    cmd = request.args.get('cmd')
    cmd = "echo safe"
    os.system(cmd)
