import os
import tempfile

import ldap
import requests
from django.db.models.expressions import RawSQL
from django.http import HttpResponseRedirect
from flask import redirect, request, send_file
from sqlalchemy import text


def queries(cursor, conn, User, tree, name, table):
    cursor.execute("SELECT * FROM t WHERE n = '%s'" % name)  # seed: py-sql-injection
    cursor.executescript("DELETE FROM t WHERE n = " + name)  # seed: py-sql-injection
    cursor.execute("SELECT * FROM %s LIMIT 10" % table)  # seed: py-sql-dynamic
    cursor.execute(name)  # seed: py-sql-api
    statement = "SELECT * FROM t WHERE n = '%s'" % name  # seed: py-sql-string-built
    tree.xpath(".//user[name/text()='%s']" % name)  # seed: py-xpath-injection
    return statement
    User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")  # seed: py-django-raw-sql
    User.objects.extra(where=["username = '%s'" % name])  # seed: py-django-raw-sql
    RawSQL("SELECT id FROM t WHERE n = '{}'".format(name), [])  # seed: py-django-raw-sql
    conn.execute(text(f"SELECT * FROM t WHERE n = '{name}'"))  # seed: py-sqlalchemy-text
    conn.search_s("dc=example,dc=org", ldap.SCOPE_SUBTREE, "(cn=" + name + ")")  # seed: py-ldap-injection


def files(name, report_path, next_url):
    upload = request.files["file"]
    open(os.path.join("/srv/data", request.args.get("file")))  # seed: py-path-traversal
    send_file(request.args["path"])  # seed: py-path-traversal
    upload.save(os.path.join("/srv/uploads", upload.filename))  # seed: py-upload-filename
    send_file(report_path)  # seed: py-send-file-api
    os.path.join("/srv/data", name)  # seed: py-path-api
    os.chmod("/srv/data/report.txt", 0o777)  # seed: py-chmod-777
    tempfile.mktemp()  # seed: py-tempfile-mktemp
    requests.get(request.args.get("url"), timeout=5)  # seed: py-ssrf
    redirect(request.args.get("next"))  # seed: py-open-redirect
    HttpResponseRedirect(request.GET["next"])  # seed: py-open-redirect
    redirect(next_url)  # seed: py-redirect-api
