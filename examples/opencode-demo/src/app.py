import os
import sqlite3
import subprocess


def find_user(username: str):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    # VULNERABLE: user input is concatenated into SQL.
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()


def run_command(command: str):
    # VULNERABLE: user input reaches a shell.
    return subprocess.check_output(command, shell=True)


if __name__ == "__main__":
    print(find_user("admin"))
    print(os.getcwd())
