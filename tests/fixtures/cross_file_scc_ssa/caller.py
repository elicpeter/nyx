from flask import request, make_response
from mutual_b import transform

def handler():
    user_input = request.args.get("q")
    safe_output = transform(user_input)
    return make_response(safe_output)
