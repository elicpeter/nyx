# Negative fixture: none of these should trigger security patterns.

import subprocess
import hashlib

def safe_subprocess():
    # No shell=True
    subprocess.run(["ls", "-la"])

def safe_hash():
    hashlib.sha256(b"data")

def safe_literal_query(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")

def safe_yaml_load(data):
    import yaml
    yaml.safe_load(data)

def safe_string_ops():
    x = "hello"
    y = x.upper()
    z = len(y)
