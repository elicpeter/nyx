def nested_safe(src, dst):
    with open(src, 'r') as reader:
        with open(dst, 'w') as writer:
            writer.write(reader.read())

def outside_leak(path):
    f = open(path, 'r')
    data = f.read()
    # f never closed — real leak
