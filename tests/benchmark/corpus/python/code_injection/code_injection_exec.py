from flask import request

def run_code():
    code = request.args.get('code')
    exec(code)
