"""A small Flask application used as a false-positive corpus.

The module deliberately mentions dangerous APIs in prose (for example eval()
and pickle.loads) so the rule engine has to ignore comments and docstrings.
"""

import logging
import os
import sqlite3

from flask import Flask, abort, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
LOGGER = logging.getLogger(__name__)
UPLOAD_DIR = "/srv/app/uploads"
ALLOWED_EXTENSIONS = {".txt", ".csv"}


def get_connection():
    connection = sqlite3.connect("/srv/app/app.db")
    connection.row_factory = sqlite3.Row
    return connection


def find_user(username):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, name FROM users WHERE name = ?", (username,))
        return cursor.fetchone()
    finally:
        connection.close()


def list_orders(customer_id):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id, total FROM orders WHERE customer_id = ?",
            (customer_id,),
        )
        return cursor.fetchall()
    finally:
        connection.close()


def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html", title="Demo")


@app.route("/user/<name>")
def user_page(name):
    record = find_user(name)
    if record is None:
        abort(404)
    return render_template("user.html", user=record)


@app.route("/orders/<int:customer_id>")
def orders_page(customer_id):
    return render_template("orders.html", orders=list_orders(customer_id))


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if uploaded is None or not allowed_file(uploaded.filename):
        abort(400)
    safe_name = secure_filename(uploaded.filename)
    destination = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(destination)
    LOGGER.info("stored upload %s", safe_name)
    return {"status": "ok", "name": safe_name}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)