import os

def process_file(path):
    f = open(path, 'r')
    header = f.readline()
    if not header.startswith('#'):
        return None  # leak: f not closed
    data = f.read()
    f.close()
    return data

def process_with_guard(path):
    if not os.path.exists(path):
        return None
    f = open(path, 'r')
    try:
        return f.read()
    finally:
        f.close()
