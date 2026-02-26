def read_and_leak(path):
    f = open(path, 'r')
    data = f.read()
    return data

def read_and_close(path):
    f = open(path, 'r')
    data = f.read()
    f.close()
    return data

def double_close(path):
    f = open(path, 'r')
    f.close()
    f.close()

def use_after_close(path):
    f = open(path, 'r')
    f.close()
    data = f.read()
    return data
