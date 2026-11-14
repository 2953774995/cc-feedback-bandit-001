import sqlite3


def lookup(db_path, name):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cond = name
    cur.execute(cond)
    conn.close()
