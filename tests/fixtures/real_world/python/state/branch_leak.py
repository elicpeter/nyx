import os

def conditional_open(path, flag):
    f = open(path, 'r')
    if flag:
        data = f.read()
        f.close()
        return data
    else:
        return "skipped"
        # f leaked in else branch
