import os
from wrapper import process

data = os.environ["INPUT"]
result = process(data)
os.system(result)
