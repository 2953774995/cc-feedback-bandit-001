from flask import request
import subprocess

ALLOWED = {"ls", "whoami", "date"}


def allow(cmd):
    if cmd in ALLOWED:
        return cmd
    return "date"


def view():
    user_cmd = request.args.get("cmd")
    cmd = allow(user_cmd)
    subprocess.run(cmd, shell=True)
