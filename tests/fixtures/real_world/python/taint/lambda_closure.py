# Python lambda captures outer var; lambda invoked later.
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/a')
def handler():
    q = request.args.get('q')
    run = lambda: os.system(q)   # lambda captures q
    run()
    return 'ok'
