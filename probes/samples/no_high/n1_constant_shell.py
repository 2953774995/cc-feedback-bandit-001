import subprocess


def listing():
    command = "ls -l /tmp"
    subprocess.run(command, shell=True)
