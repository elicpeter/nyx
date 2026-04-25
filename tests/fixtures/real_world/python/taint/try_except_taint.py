import os
user_cmd = input()
try:
    os.system(user_cmd)
except Exception as e:
    print(f"Error: {e}")
