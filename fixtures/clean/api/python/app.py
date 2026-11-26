import os


def fetch(cursor):
    cursor.execute("SELECT 1")
    os.system("ls -l")
    return os.path.join("/data", "static.txt")
