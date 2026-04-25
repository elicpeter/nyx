import os


def get_raw_input():
    """SOURCE: reads an env variable that is fully user-controlled at runtime.

    This is the first file in a three-hop taint chain:
      input_reader.py  →  transform.py  →  executor.py
    """
    return os.environ.get("USER_CMD")
