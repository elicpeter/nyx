import os
from helpers import process_input

def handler():
    user_input = os.environ.get("INPUT")
    process_input("echo hello", user_input)  # SAFE: tainted data in param 1 (non-sink)
    process_input(user_input, "debug")       # UNSAFE: tainted data in param 0 (CMD sink)
