import requests

def fetch_status():
    url = 'https://api.example.com/health'
    resp = requests.get(url)
    return resp.status_code
