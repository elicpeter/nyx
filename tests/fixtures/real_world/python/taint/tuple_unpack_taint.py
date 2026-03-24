import os
import subprocess

def get_config():
    return os.getenv("HOST"), os.getenv("PORT")

host, port = get_config()
subprocess.run(["curl", host])
