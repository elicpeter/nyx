import os
import subprocess
import html

def get_env_value():
    return os.environ.get("SECRET_KEY", "")

def sanitize_input(val):
    return html.escape(val)

def execute_command(cmd):
    subprocess.run(cmd, shell=True)

def safe_flow():
    val = get_env_value()
    clean = sanitize_input(val)
    print(clean)

def unsafe_flow():
    val = get_env_value()
    execute_command(val)

if __name__ == "__main__":
    safe_flow()
    unsafe_flow()
