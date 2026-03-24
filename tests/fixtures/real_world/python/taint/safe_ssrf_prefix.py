from flask import request
import requests

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    url = 'https://api.internal.example.com/users/' + user_id
    resp = requests.get(url)
    return resp.json()
