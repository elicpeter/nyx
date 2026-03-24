import html
from flask import request

def escape_user_input(s):
    return html.escape(s)

def show_profile():
    name = request.args.get('name')
    safe_name = escape_user_input(name)
    return '<h1>' + safe_name + '</h1>'
