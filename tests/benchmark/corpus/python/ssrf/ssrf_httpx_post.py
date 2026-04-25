import httpx
from flask import request as flask_request

def proxy():
    url = flask_request.args.get('url')
    resp = httpx.post(url, data={"key": "value"})
    return resp.text
