from flask import Flask, request
import httpx

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = httpx.post(url, data={"key": "value"})
    return resp.text
