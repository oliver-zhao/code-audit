"""Flask seeds for the Opengrep taint rules (rules/opengrep/python-taint.yml).

This file is test data. It is never imported or executed.

Every sink line ends with a comment naming the rule expected to report it. The flows are
deliberately multi-step: the request value is renamed, formatted into a larger
string, or handed to a helper function in this file before it reaches the
sink, which a line-based matcher cannot follow.
"""

import base64
import os
import pickle
import sqlite3
import subprocess
import urllib.request

import requests
import yaml
from flask import Flask, make_response, redirect, render_template_string, request, send_file
from jinja2 import Template
from sqlalchemy import text

app = Flask(__name__)
db = sqlite3.connect("app.db")
UPLOAD_DIR = "/srv/uploads"
REPORT_DIR = "/srv/reports"


# --- SQL injection (CWE-89) -------------------------------------------------


@app.route("/users")
def sql_assignment_chain():
    raw = request.args.get("name")
    trimmed = raw.strip()
    name = trimmed.lower()
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor = db.cursor()
    cursor.execute(query)  # expect: py-taint-sql
    return str(cursor.fetchall())


def find_orders(cursor, customer):
    sql = "SELECT * FROM orders WHERE customer = '{}'".format(customer)
    cursor.execute(sql)  # expect: py-taint-sql
    return cursor.fetchall()


@app.route("/orders", methods=["POST"])
def sql_helper_sink():
    customer = request.form["customer"]
    return str(find_orders(db.cursor(), customer))


def build_filter(column, value):
    return column + " = '" + value + "'"


@app.route("/search")
def sql_helper_return():
    where = build_filter("title", request.values.get("q", ""))
    statement = f"SELECT id FROM books WHERE {where}"
    rows = db.execute(statement)  # expect: py-taint-sql
    return str(rows.fetchall())


@app.route("/items/<category>")
def sql_path_parameter(category):
    statement = "SELECT * FROM items WHERE category = '" + category + "'"
    return str(db.execute(text(statement)))  # expect: py-taint-sql


@app.route("/import", methods=["POST"])
def sql_script():
    script = "INSERT INTO notes(body) VALUES ('" + request.get_json()["body"] + "');"
    db.executescript(script)  # expect: py-taint-sql
    return "ok"


@app.route("/signin", methods=["POST"])
def sql_sink_inside_conversion():
    password = request.form.get("password", "")
    found = bool(db.execute("SELECT 1 FROM users WHERE password = '" + password + "'").fetchall())  # expect: py-taint-sql
    return "welcome" if found else "denied"


# --- OS command injection (CWE-78) ------------------------------------------


@app.route("/ping")
def command_fstring():
    host = request.args.get("host", "")
    target = host.strip()
    command = f"ping -c 1 {target}"
    os.system(command)  # expect: py-taint-command
    return "done"


def archive_command(folder):
    return "tar czf /tmp/backup.tgz " + folder


@app.route("/backup", methods=["POST"])
def command_helper_return():
    command = archive_command(request.form.get("folder"))
    subprocess.run(command, shell=True)  # expect: py-taint-command
    return "done"


def run_lookup(domain):
    return query_dns("nslookup " + domain)


def query_dns(command_line):
    return os.popen(command_line).read()  # expect: py-taint-command


@app.route("/lookup")
def command_two_helpers():
    agent = request.headers.get("X-Lookup-Domain")
    return run_lookup(agent)


@app.route("/convert/<tool>")
def command_program_from_path(tool):
    output = subprocess.check_output([tool, "--version"])  # expect: py-taint-command
    return output


# --- Path traversal (CWE-22) ------------------------------------------------


@app.route("/report")
def path_join_chain():
    name = request.args.get("name")
    relative = name + ".pdf"
    full_path = os.path.join(REPORT_DIR, relative)
    with open(full_path, "rb") as handle:  # expect: py-taint-path
        return handle.read()


@app.route("/download/<path:filename>")
def path_parameter(filename):
    return send_file(REPORT_DIR + "/" + filename)  # expect: py-taint-path


@app.route("/upload", methods=["POST"])
def path_upload_client_name():
    upload = request.files["file"]
    destination = os.path.join(UPLOAD_DIR, upload.filename)
    upload.save(destination)  # expect: py-taint-path
    return "saved"


def upload_path(name):
    return os.path.join(UPLOAD_DIR, name)


@app.route("/delete", methods=["POST"])
def path_helper_return():
    victim = upload_path(request.form["name"])
    os.remove(victim)  # expect: py-taint-path
    return "deleted"


# --- Server-side request forgery (CWE-918) ----------------------------------


@app.route("/preview", methods=["POST"])
def ssrf_json_chain():
    payload = request.json
    link = payload["url"]
    response = requests.get(link, timeout=5)  # expect: py-taint-ssrf
    return response.text


def download(url):
    return urllib.request.urlopen(url, timeout=5).read()  # expect: py-taint-ssrf


@app.route("/avatar")
def ssrf_helper_sink():
    return download(request.args["src"])


@app.route("/status")
def ssrf_host_in_fstring():
    host = request.args.get("host")
    endpoint = f"http://{host}/status"
    return requests.post(endpoint, timeout=5).text  # expect: py-taint-ssrf


# --- Server-side template injection (CWE-1336) ------------------------------


@app.route("/hello")
def template_percent():
    name = request.args.get("name", "world")
    page = "<h1>Hello %s</h1>" % name
    return render_template_string(page)  # expect: py-taint-template


def render_banner(source):
    return Template(source).render()  # expect: py-taint-template


@app.route("/banner")
def template_helper_sink():
    greeting = request.cookies.get("greeting")
    return render_banner("<b>" + greeting + "</b>")


# --- Open redirect (CWE-601) ------------------------------------------------


@app.route("/login", methods=["POST"])
def redirect_next():
    destination = request.args.get("next")
    target = destination or "/"
    return redirect(target)  # expect: py-taint-redirect


def go(target):
    return redirect(target)  # expect: py-taint-redirect


@app.route("/out")
def redirect_helper_sink():
    return go(request.values["url"])


# --- Unsafe deserialization (CWE-502) ---------------------------------------


@app.route("/session")
def deserialize_cookie():
    cookie = request.cookies["session"]
    blob = base64.b64decode(cookie)
    return str(pickle.loads(blob))  # expect: py-taint-deserialization


def parse_config(document):
    return yaml.load(document, Loader=yaml.Loader)  # expect: py-taint-deserialization


@app.route("/config", methods=["POST"])
def deserialize_yaml_helper():
    body = request.data
    return str(parse_config(body))


@app.route("/settings", methods=["POST"])
def deserialize_yaml_default_loader():
    document = request.get_data(as_text=True)
    return str(yaml.load(document))  # expect: py-taint-deserialization


# --- eval / exec (CWE-95) ---------------------------------------------------


@app.route("/calc")
def eval_chain():
    expression = request.args.get("expr")
    cleaned = expression.replace(" ", "")
    return str(eval(cleaned))  # expect: py-taint-eval


def run_snippet(code):
    scope = {}
    exec(code, scope)  # expect: py-taint-eval
    return scope


@app.route("/hook", methods=["POST"])
def exec_helper_sink():
    snippet = request.form.get("code")
    return str(run_snippet("result = " + snippet))


# --- Cross-site scripting (CWE-79) ------------------------------------------


@app.route("/welcome")
def xss_greeting():
    who = request.args.get("who", "")
    banner = "<h1>Welcome " + who + "</h1>"
    return make_response(banner)  # expect: py-taint-xss


# --- NoSQL injection (CWE-943) ----------------------------------------------


@app.route("/api/orders", methods=["POST"])
def nosql_filter_from_body():
    criteria = request.get_json()
    order = mongo.shop.orders.find_one(criteria)  # expect: py-taint-nosql
    return {"id": str(order["_id"])}


# --- LDAP injection (CWE-90) ------------------------------------------------


@app.route("/directory")
def ldap_filter_chain():
    uid = request.args["uid"]
    query = "(&(uid=%s)(objectClass=person))" % uid
    entries = directory.search_s("dc=example,dc=com", 2, query)  # expect: py-taint-ldap
    return {"count": len(entries)}
