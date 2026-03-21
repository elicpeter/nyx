import pickle
from flask import request

def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)
