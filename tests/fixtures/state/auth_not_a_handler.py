import subprocess

def process_data(batch):
    subprocess.run(batch["cmd"])
