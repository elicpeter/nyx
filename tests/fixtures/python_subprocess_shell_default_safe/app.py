from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route('/shell_default_safe')
def shell_default_safe():
    cmd = request.args.get('cmd')
    result = subprocess.run([cmd], capture_output=True)
    return result.stdout.decode()
