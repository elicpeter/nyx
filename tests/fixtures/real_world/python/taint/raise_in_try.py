import os
val = input()
try:
    if not val:
        raise ValueError("bad")
    os.system(val)
except ValueError as e:
    pass
