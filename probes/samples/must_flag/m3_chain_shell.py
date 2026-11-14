from flask import request
import subprocess


def view():
    raw = request.form.get("cmd")
    cmd = raw
    picked = cmd
    subprocess.run(picked, shell=True)
