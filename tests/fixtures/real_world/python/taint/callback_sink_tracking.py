# Callback tracking: os.system passed as callback to invoke(), tainted data flows through.
import os
from flask import request

def invoke(data, handler):
    handler(data)

user_input = request.args.get('cmd')
invoke(user_input, os.system)
