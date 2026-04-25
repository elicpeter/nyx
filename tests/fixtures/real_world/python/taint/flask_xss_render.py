from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name')
    resp = make_response('<h1>Hello ' + name + '</h1>')
    resp.headers['Content-Type'] = 'text/html'
    return resp
