from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/uploads', filename)
    return send_file(filepath)

@app.route('/download-safe')
def download_safe():
    filename = request.args.get('file')
    filepath = os.path.join('/uploads', filename)
    realpath = os.path.realpath(filepath)
    if not realpath.startswith('/uploads'):
        return 'Forbidden', 403
    return send_file(realpath)
