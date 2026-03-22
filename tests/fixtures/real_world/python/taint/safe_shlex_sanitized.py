import os
import shlex
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    safe_host = shlex.quote(host)
    os.system('ping -c 1 ' + safe_host)
    return 'done'
