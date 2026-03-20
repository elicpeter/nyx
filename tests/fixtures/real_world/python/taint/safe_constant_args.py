import os
import subprocess

os.system("ls -la /tmp")
result = subprocess.run(["date"], capture_output=True)
print(result.stdout.decode())
