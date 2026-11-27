"""Deliberately vulnerable demo service for trying code-audit. Do not deploy."""
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, redirect, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "demo-7f3a9c1b2d4e5f60718293a4b5c6d7e8"


def get_db():
    return sqlite3.connect("demo.db")


@app.route("/users")
def users():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    cursor.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
    return {"users": cursor.fetchall()}


@app.route("/users/safe")
def users_safe():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return {"users": cursor.fetchall()}


def build_report_command(fmt):
    return "report-tool --format " + fmt


@app.route("/report")
def report():
    fmt = request.args.get("format", "pdf")
    command = build_report_command(fmt)
    return subprocess.run(command, shell=True, capture_output=True).stdout


@app.route("/session", methods=["POST"])
def restore_session():
    return {"session": str(pickle.loads(request.data))}


@app.route("/config", methods=["POST"])
def load_config():
    return yaml.load(request.data, Loader=yaml.Loader)


@app.route("/go")
def go():
    return redirect(request.args["next"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
