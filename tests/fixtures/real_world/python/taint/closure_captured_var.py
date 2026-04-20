# Python: nested def captures outer var, then inner() is called.
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/a')
def handler():
    q = request.args.get('q')   # source
    def inner():
        os.system(q)            # sink on captured source
    inner()
    return 'ok'
