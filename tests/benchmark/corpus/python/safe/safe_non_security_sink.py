import logging
from flask import request

def log_input():
    name = request.args.get('name')
    logging.info("User requested: " + name)
    length = len(name)
    return str(length)
