from flask import Flask, request
import subprocess

app = Flask(__name__)

def add_to_list(items, value):
    items.append(value)
    return items

@app.route('/interproc')
def interproc():
    cmds = []
    result = add_to_list(cmds, request.args.get('cmd'))
    subprocess.run(result)
