"""Safe Flask counterparts of fixtures/vulnerable/python/taint_app.py.

This file is test data. It is never imported or executed.

Each view reads the same request data as its vulnerable twin, but the value is
bound as a query parameter, converted to a number, reduced to a file name,
looked up in an allow-list mapping, or never reaches the sink. The Opengrep
taint rules must report nothing in this file.
"""

import ast
import html
import json
import os
import shlex
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, Response, make_response, redirect, render_template, request, send_from_directory, url_for
from sqlalchemy import text
from ldap.filter import escape_filter_chars
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("app.db")
UPLOAD_DIR = "/srv/uploads"
REPORT_DIR = "/srv/reports"
SORT_COLUMNS = {"name": "name", "date": "created_at"}
LANDING_PAGES = {"home": "/", "inbox": "/inbox"}
API_BASE = "https://api.example.com"


# --- SQL: bound parameters, numeric conversion, allow-listed identifiers ----


@app.route("/users")
def sql_bound_parameter():
    raw = request.args.get("name")
    name = raw.strip().lower()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cursor.fetchall())


def find_orders(cursor, customer):
    cursor.execute("SELECT * FROM orders WHERE customer = ?", [customer])
    return cursor.fetchall()


@app.route("/orders", methods=["POST"])
def sql_helper_bound_parameter():
    customer = request.form["customer"]
    return str(find_orders(db.cursor(), customer))


@app.route("/search")
def sql_allow_listed_column():
    column = SORT_COLUMNS[request.values.get("sort", "name")]
    statement = f"SELECT id FROM books ORDER BY {column}"
    return str(db.execute(statement).fetchall())


@app.route("/items/<category>")
def sql_named_parameter(category):
    statement = text("SELECT * FROM items WHERE category = :category")
    return str(db.execute(statement, {"category": category}))


@app.route("/page")
def sql_numeric_conversion():
    offset = int(request.args.get("offset", "0"))
    rows = db.execute("SELECT id FROM books LIMIT 20 OFFSET %d" % offset)
    return str(rows.fetchall())


@app.route("/import", methods=["POST"])
def sql_many_bound_rows():
    rows = [(note["body"],) for note in request.get_json()]
    db.executemany("INSERT INTO notes(body) VALUES (?)", rows)
    return "ok"


# --- OS command: argument list without a shell, or shell quoting -----------


@app.route("/ping")
def command_argument_list():
    host = request.args.get("host", "").strip()
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "done"


def archive_command(folder):
    return "tar czf /tmp/backup.tgz " + shlex.quote(folder)


@app.route("/backup", methods=["POST"])
def command_quoted():
    command = archive_command(request.form.get("folder"))
    subprocess.run(shlex.split(command), check=False)
    return "done"


@app.route("/convert/<tool>")
def command_fixed_program(tool):
    quality = int(request.args.get("quality", "80"))
    output = subprocess.check_output(["convert", "--quality", str(quality)])
    return output


# --- Path: file name only -------------------------------------------------


@app.route("/report")
def path_basename():
    name = os.path.basename(request.args.get("name"))
    full_path = os.path.join(REPORT_DIR, name + ".pdf")
    with open(full_path, "rb") as handle:
        return handle.read()


@app.route("/download/<path:filename>")
def path_send_from_directory(filename):
    return send_from_directory(REPORT_DIR, filename)


def stored_name(upload):
    return secure_filename(upload.filename)


@app.route("/upload", methods=["POST"])
def path_secure_filename_helper():
    upload = request.files["file"]
    destination = os.path.join(UPLOAD_DIR, stored_name(upload))
    upload.save(destination)
    return "saved"


@app.route("/delete", methods=["POST"])
def path_numeric_identifier():
    number = int(request.form["id"])
    os.remove(os.path.join(UPLOAD_DIR, "%d.bin" % number))
    return "deleted"


# --- SSRF: fixed scheme and host ----------------------------------------------


@app.route("/preview", methods=["POST"])
def ssrf_fixed_host():
    item = request.json["item"]
    response = requests.get("https://api.example.com/items/" + item, timeout=5)
    return response.text


@app.route("/status")
def ssrf_query_parameter_only():
    host = request.args.get("host")
    return requests.get(API_BASE + "/status", params={"host": host}, timeout=5).text


@app.route("/avatar")
def ssrf_fixed_host_fstring():
    user = request.args["user"]
    return requests.get(f"https://img.example.com/avatars/{user}.png", timeout=5).content


# --- Templates: constant template, request data as context -----------------


@app.route("/hello")
def template_context_variable():
    name = request.args.get("name", "world")
    return render_template("hello.html", name=name)


@app.route("/banner")
def template_context_from_cookie():
    greeting = request.cookies.get("greeting")
    return render_template("banner.html", greeting=greeting)


# --- Redirect: fixed targets ----------------------------------------------


@app.route("/login", methods=["POST"])
def redirect_allow_listed():
    target = LANDING_PAGES.get(request.args.get("next"), "/")
    return redirect(target)


@app.route("/out")
def redirect_url_for():
    return redirect(url_for("profile", name=request.values["name"]))


@app.route("/tag")
def redirect_local_prefix():
    return redirect("/tags/" + request.args["tag"])


# --- Deserialization: data-only formats ------------------------------------


@app.route("/session")
def deserialize_json():
    cookie = request.cookies["session"]
    return str(json.loads(cookie))


def parse_config(document):
    return yaml.safe_load(document)


@app.route("/config", methods=["POST"])
def deserialize_safe_yaml_helper():
    return str(parse_config(request.data))


@app.route("/settings", methods=["POST"])
def deserialize_safe_loader():
    document = request.get_data(as_text=True)
    return str(yaml.load(document, Loader=yaml.SafeLoader))


# --- eval / exec: literal parsing only -------------------------------------


@app.route("/calc")
def literal_eval_only():
    expression = request.args.get("expr")
    return str(ast.literal_eval(expression))


@app.route("/double")
def numeric_arithmetic():
    value = float(request.args.get("value", "0"))
    return str(value * 2)


@app.route("/welcome")
def xss_greeting():
    who = request.args.get("who", "")
    banner = "<h1>Welcome " + html.escape(who) + "</h1>"
    return make_response(banner)


@app.route("/welcome.txt")
def text_greeting():
    who = request.args.get("who", "")
    return Response("Welcome " + who, mimetype="text/plain")


@app.route("/api/orders", methods=["POST"])
def nosql_filter_from_body():
    criteria = request.get_json()
    order = mongo.shop.orders.find_one({"customer": str(criteria.get("customer", ""))})
    position = request.args.get("q", "").find("x")
    return {"id": str(order["_id"]), "position": position}


@app.route("/directory")
def ldap_filter_chain():
    uid = escape_filter_chars(request.args["uid"])
    query = "(&(uid=%s)(objectClass=person))" % uid
    entries = directory.search_s("dc=example,dc=com", 2, query)
    return {"count": len(entries)}


@app.route("/back")
def go_back():
    return make_response(redirect("/items/" + request.args["id"]))
