import os
from transform import transform_input

def handle():
    data = os.environ["USER_CMD"]
    result = transform_input(data)
