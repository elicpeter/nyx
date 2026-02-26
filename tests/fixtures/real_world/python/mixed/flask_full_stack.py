from flask import Flask, request
import subprocess
import os

app = Flask(__name__)

@app.route('/api/exec')
def execute():
    cmd = request.args.get('cmd')
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

@app.route('/api/read')
def read_file():
    path = request.args.get('path')
    f = open(path, 'r')
    data = f.read()
    return data
    # f leaked + path traversal taint

@app.route('/api/eval')
def eval_expr():
    expr = request.args.get('expr')
    return str(eval(expr))
