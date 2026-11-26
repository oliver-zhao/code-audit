import os
import sqlite3


def lookup(name: str):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # VULNERABLE: string concatenation builds the SQL statement.
    cursor.execute("SELECT * FROM accounts WHERE name = '" + name + "'")
    return cursor.fetchall()


if __name__ == "__main__":
    print(lookup("admin"))
    print(os.getcwd())
