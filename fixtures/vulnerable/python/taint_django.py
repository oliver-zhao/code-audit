"""Django seeds for the Opengrep taint rules (rules/opengrep/python-taint.yml).

This file is test data. It is never imported or executed.

Every sink line ends with a comment naming the rule expected to report it.
"""

import os
import pickle
import subprocess

import requests
from django.db import connection
from django.db.models.expressions import RawSQL
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.template import Template, Context
from django.views import View

from shop.models import Invoice, Product

MEDIA_ROOT = "/srv/media"


def product_search(request):
    term = request.GET.get("q", "")
    pattern = "%" + term + "%"
    sql = "SELECT * FROM shop_product WHERE name LIKE '" + pattern + "'"
    products = Product.objects.raw(sql)  # expect: py-taint-sql
    return HttpResponse(", ".join(p.name for p in products))


def invoice_filter(request):
    status = request.POST["status"]
    clause = "status = '%s'" % status
    invoices = Invoice.objects.extra(where=[clause])  # expect: py-taint-sql
    return HttpResponse(str(invoices.count()))


def invoice_totals(request):
    column = request.GET["column"]
    annotated = Invoice.objects.annotate(total=RawSQL("SELECT SUM(" + column + ")", []))  # expect: py-taint-sql
    return HttpResponse(str(annotated))


def invoice_detail(request, reference):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM shop_invoice WHERE reference = '%s'" % reference)  # expect: py-taint-sql
        row = cursor.fetchone()
    return HttpResponse(str(row))


def export_table(table):
    command = "pg_dump --table=" + table
    return subprocess.check_output(command, shell=True)  # expect: py-taint-command


class ExportView(View):
    def post(self, request):
        table = request.POST.get("table")
        return HttpResponse(export_table(table))


class AttachmentView(View):
    def get(self, request, name):
        location = os.path.join(MEDIA_ROOT, "attachments", name)
        return FileResponse(open(location, "rb"))  # expect: py-taint-path


def webhook_test(request):
    callback = request.headers.get("X-Callback-Url")
    result = requests.post(callback, json={"ok": True}, timeout=5)  # expect: py-taint-ssrf
    return HttpResponse(str(result.status_code))


def greeting(request):
    who = request.GET.get("who", "guest")
    template = Template("Hello " + who)  # expect: py-taint-template
    return HttpResponse(template.render(Context({})))


def after_login(request):
    target = request.GET.get("next")
    return HttpResponseRedirect(target)  # expect: py-taint-redirect


def leave(request):
    referer = request.META.get("HTTP_REFERER")
    return redirect(referer)  # expect: py-taint-redirect


def restore_cart(request):
    raw = request.COOKIES.get("cart")
    cart = pickle.loads(bytes.fromhex(raw))  # expect: py-taint-deserialization
    return HttpResponse(str(cart))


def formula(request):
    body = request.body.decode("utf-8")
    value = eval(body)  # expect: py-taint-eval
    return HttpResponse(str(value))
