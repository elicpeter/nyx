from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route('/shell_true_tainted')
def shell_true_tainted():
    cmd = request.args.get('cmd')
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
