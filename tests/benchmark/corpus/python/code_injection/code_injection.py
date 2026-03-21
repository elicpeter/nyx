from flask import request

def calculate():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
