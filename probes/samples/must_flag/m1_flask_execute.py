from flask import request
import sqlite3


def view():
    raw = request.args.get("id")
    q = raw
    conn = sqlite3.connect("app.db")
    conn.cursor().execute(q)
