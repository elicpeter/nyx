import subprocess


def check_disk():
    cmd = ["df", "-h", "/"]
    result = subprocess.run(cmd, capture_output=True)
    return result.stdout.decode()
