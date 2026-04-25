from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route('/shell_false_safe')
def shell_false_safe():
    cmd = request.args.get('cmd')
    result = subprocess.run([cmd], shell=False, capture_output=True)
    return result.stdout.decode()
