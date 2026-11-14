import sqlite3


def lookup(db_path, name):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE id = ?", (name,))
    conn.close()
