from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/alias')
def run():
    a = []
    b = a
    a.append(request.args.get('cmd'))
    subprocess.call(b)
    return 'done'
