import subprocess

from transform import prepare_command


def run():
    """SINK: subprocess.call with shell=True on a command that originated from
    os.environ two hops away (input_reader.py → transform.py → here).

    VULN: no sanitisation at any point in the three-file chain.
    """
    cmd = prepare_command("--verbose")
    subprocess.call(cmd, shell=True)  # shell=True + tainted cmd → cmdi
