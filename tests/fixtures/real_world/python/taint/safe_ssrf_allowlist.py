from flask import Flask, request
import httpx

app = Flask(__name__)
ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return 'Forbidden', 403
    resp = httpx.get(url)
    return resp.text
