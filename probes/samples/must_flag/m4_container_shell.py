import sys
import subprocess


def main():
    args = {"cmd": sys.argv[1]}
    parts = [args["cmd"], "-l"]
    subprocess.Popen(parts, shell=True)
