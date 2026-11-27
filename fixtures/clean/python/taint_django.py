"""Safe Django counterparts of fixtures/vulnerable/python/taint_django.py.

This file is test data. It is never imported or executed. The Opengrep taint
rules must report nothing in this file.
"""

import json
import os
import subprocess

import requests
from django.db import connection
from django.db.models.expressions import RawSQL
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.utils.html import escape
from ldap3.utils.conv import escape_filter_chars
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View

from shop.models import Invoice, Product

MEDIA_ROOT = "/srv/media"
EXPORT_TABLES = {"orders": "shop_order", "invoices": "shop_invoice"}


def product_search(request):
    term = request.GET.get("q", "")
    pattern = "%" + term + "%"
    products = Product.objects.raw("SELECT * FROM shop_product WHERE name LIKE %s", [pattern])
    return HttpResponse(", ".join(p.name for p in products))


def invoice_filter(request):
    status = request.POST["status"]
    invoices = Invoice.objects.extra(where=["status = %s"], params=[status])
    return HttpResponse(str(invoices.count()))


def invoice_totals(request):
    minimum = request.GET["minimum"]
    annotated = Invoice.objects.annotate(total=RawSQL("SELECT SUM(amount) WHERE amount > %s", [minimum]))
    return HttpResponse(str(annotated))


def invoice_detail(request, reference):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM shop_invoice WHERE reference = %s", [reference])
        row = cursor.fetchone()
    return HttpResponse(str(row))


def invoice_by_number(request, number: int):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM shop_invoice WHERE id = %d" % number)
        row = cursor.fetchone()
    return HttpResponse(str(row))


def export_table(table):
    return subprocess.check_output(["pg_dump", "--table=" + table])


class ExportView(View):
    def post(self, request):
        table = EXPORT_TABLES[request.POST.get("table")]
        return HttpResponse(export_table(table))


class AttachmentView(View):
    def get(self, request, name):
        location = os.path.join(MEDIA_ROOT, "attachments", os.path.basename(name))
        return FileResponse(open(location, "rb"))


def webhook_test(request):
    event = request.headers.get("X-Event-Name")
    result = requests.post("https://hooks.example.com/events", json={"event": event}, timeout=5)
    return HttpResponse(str(result.status_code))


def greeting(request):
    who = request.GET.get("who", "guest")
    return render(request, "greeting.html", {"who": who})


def after_login(request):
    return HttpResponseRedirect(reverse("dashboard"))


def leave(request, section):
    return redirect("/sections/" + section)


def restore_cart(request):
    raw = request.COOKIES.get("cart")
    cart = json.loads(raw)
    return HttpResponse(str(cart))


def formula(request):
    body = request.body.decode("utf-8")
    value = int(body) * 2
    return HttpResponse(str(value))


def greeting(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"<p>Hello {escape(name)}</p>")


def plain_greeting(request):
    name = request.GET.get("name", "")
    return HttpResponse("Hello " + name, content_type="text/plain")


def order_where(request):
    customer = request.GET["customer"]
    rows = orders.find({"customer": customer})
    return HttpResponse(str(len(list(rows))))


def staff_lookup(request, username):
    search_filter = f"(uid={escape_filter_chars(username)})"
    conn.search("ou=staff,dc=example,dc=com", search_filter)
    return HttpResponse(str(len(conn.entries)))


def word_search(request):
    import re

    return HttpResponse(str(bool(re.search("^[a-z]+$", request.GET.get("q", "")))))
