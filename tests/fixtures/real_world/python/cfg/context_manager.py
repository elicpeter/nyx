def read_file_unsafe(path):
    f = open(path, 'r')
    data = f.read()
    return data
    # f never closed

def read_file_safe(path):
    with open(path, 'r') as f:
        data = f.read()
    return data

def nested_context(path1, path2):
    with open(path1, 'r') as f1:
        with open(path2, 'w') as f2:
            f2.write(f1.read())
