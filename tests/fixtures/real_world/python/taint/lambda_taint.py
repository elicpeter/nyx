import os

def handle():
    user_input = input()
    # Lambda should be its own body — taint flows through parameter
    dangerous = (lambda cmd: os.system(cmd))(user_input)
