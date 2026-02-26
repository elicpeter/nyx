from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd')
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

@app.route('/run-safe')
def run_cmd_safe():
    cmd = request.args.get('cmd')
    allowed = ['ls', 'date', 'whoami']
    if cmd not in allowed:
        return 'Not allowed', 403
    result = subprocess.run([cmd], capture_output=True)
    return result.stdout.decode()
