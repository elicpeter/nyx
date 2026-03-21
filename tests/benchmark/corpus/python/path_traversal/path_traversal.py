from flask import request, send_file

def download():
    path = request.args.get('path')
    return send_file(path)
