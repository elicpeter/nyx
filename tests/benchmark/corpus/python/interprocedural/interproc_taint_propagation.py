import os
from flask import request

def build_command(user_filter):
    return 'grep ' + user_filter + ' /var/log/app.log'

def search_logs():
    f = request.args.get('filter')
    cmd = build_command(f)
    os.system(cmd)
