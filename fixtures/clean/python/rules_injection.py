import os
import tempfile

import ldap
import requests
from django.db.models.expressions import RawSQL
from django.http import HttpResponseRedirect
from django.urls import reverse
from flask import redirect, request, send_from_directory, url_for
from ldap.filter import escape_filter_chars
from sqlalchemy import text
from werkzeug.utils import secure_filename


def queries(cursor, conn, User, tree, name):
    cursor.execute("SELECT * FROM t WHERE n = ?", (name,))
    cursor.execute("SELECT * FROM t WHERE n = %s", [name])
    cursor.executemany("INSERT INTO t (n) VALUES (?)", [(name,)])
    with open(os.path.join(os.path.dirname(__file__), "data.sql")) as handle:
        cursor.executescript(handle.read())
    User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
    User.objects.extra(where=["username = %s"], params=[name])
    RawSQL("SELECT id FROM t WHERE n = %s", [name])
    conn.execute(text("SELECT * FROM t WHERE n = :n"), {"n": name})
    statement = "SELECT * FROM t WHERE n = ?"
    banner = "select a plan from %s options" % name
    tree.xpath(".//user[name/text()=$n]", n=name)
    tree.findall("./user/" + "name")
    os.path.join(os.path.dirname(__file__), "templates", "page.html")
    conn.search_s("dc=example,dc=org", ldap.SCOPE_SUBTREE, "(cn=%s)" % escape_filter_chars(name))


def files(name, filename):
    upload = request.files["file"]
    open(filename, "rb")
    open("/srv/data/static.txt")
    send_from_directory("/srv/data", name)
    upload.save(os.path.join("/srv/uploads", secure_filename(upload.filename)))
    os.chmod("/srv/data/report.txt", 0o640)
    handle, path = tempfile.mkstemp()
    requests.get("https://example.invalid/api", params={"q": name}, timeout=5)
    redirect(url_for("auth.login"))
    redirect("/home")
    HttpResponseRedirect(reverse("home"))
    return handle, path
