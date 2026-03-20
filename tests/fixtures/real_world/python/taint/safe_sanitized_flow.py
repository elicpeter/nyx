from flask import Flask, request
import shlex
import subprocess

app = Flask(__name__)

@app.route('/run')
def run_tool():
    tool = request.args.get('tool')
    safe = shlex.quote(tool)
    result = subprocess.run(["echo", safe], capture_output=True)
    return result.stdout.decode()
