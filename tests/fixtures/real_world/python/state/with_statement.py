def safe_with(path):
    with open(path, 'r') as f:
        return f.read()

def nested_with(src, dst):
    with open(src, 'r') as reader:
        with open(dst, 'w') as writer:
            writer.write(reader.read())

def conditional_with(path, mode):
    if mode == 'read':
        with open(path, 'r') as f:
            return f.read()
    else:
        f = open(path, 'w')
        f.write('default')
        # f not closed in else branch
