from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/save')
def save_data():
    filename = request.args.get('name')
    data = request.args.get('data')
    filepath = os.path.join('/tmp', filename)
    f = open(filepath, 'w')
    f.write(data)
    if len(data) > 10000:
        return 'Too large', 413
        # f leaks on early return
    f.close()
    return 'OK'
