import requests

def health_check():
    resp = requests.get("https://api.example.com/health")
    return resp.status_code
