import os
from helper import run_cmd


def main():
    cmd = os.environ["USER_CMD"]
    run_cmd(cmd)


if __name__ == "__main__":
    main()
