from flask import request
import subprocess


def view():
    user_cmd = request.args.get("cmd")
    cmd = "ls -l"
    subprocess.run(cmd, shell=True)
