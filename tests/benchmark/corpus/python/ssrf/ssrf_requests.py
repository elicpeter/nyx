import requests
from flask import request as flask_request

def proxy():
    url = flask_request.args.get('url')
    resp = requests.get(url)
    return resp.text
