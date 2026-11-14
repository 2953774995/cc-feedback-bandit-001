import shlex
import sys
import subprocess


def main():
    safe_cmd = shlex.quote(sys.argv[1])
    subprocess.run(safe_cmd, shell=True)
