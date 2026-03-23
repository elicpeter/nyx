from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    commands = []
    commands.append(request.args.get('cmd'))
    subprocess.call(commands)
    return 'done'
