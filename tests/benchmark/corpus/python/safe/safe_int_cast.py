import subprocess
from flask import request

def run_limited():
    count = int(request.args.get('count'))
    subprocess.run(['seq', str(count)])
