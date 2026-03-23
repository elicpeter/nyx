import os
import subprocess
from sanitizer import clean_html

def run():
    data = os.environ["INPUT"]
    safe = clean_html(data)
    subprocess.call(safe, shell=True)
