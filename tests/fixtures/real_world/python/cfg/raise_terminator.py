from flask import Flask, request
import subprocess

app = Flask(__name__)

class ValidationError(Exception):
    pass

def validate_cmd(cmd):
    if not cmd.isalnum():
        raise ValidationError("Invalid command")
    return cmd

@app.route('/exec')
def exec_cmd():
    cmd = request.args.get('cmd')
    validated = validate_cmd(cmd)
    result = subprocess.run([validated], capture_output=True)
    return result.stdout.decode()
