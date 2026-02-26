from flask import Flask, request
import pickle
import base64

app = Flask(__name__)

@app.route('/load', methods=['POST'])
def load_object():
    data = request.get_data()
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)
    return str(obj)
