import sqlite3


def my_view(request):
    raw = request.GET.get("id")
    q = raw
    conn = sqlite3.connect("app.db")
    conn.cursor().execute(q)
