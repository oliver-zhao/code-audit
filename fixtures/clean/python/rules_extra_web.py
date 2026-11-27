"""Safe counterparts of fixtures/vulnerable/python/rules_extra_web.py.

Never write return "<h1>" + request.args["name"] or requests.get(f"http://{request.args['host']}/").
"""
import re
from urllib.parse import urlparse

import jwt
import ldap
import requests
from django.http import HttpResponse, JsonResponse
from django.utils.html import escape, format_html
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from flask import Flask, jsonify, make_response, render_template, request
from flask_cors import CORS
from ldap.filter import escape_filter_chars
from markupsafe import escape as html_escape
from pymongo import MongoClient

app = Flask(__name__)
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
db = MongoClient()["shop"]
ALLOWED_HOSTS = {"status.example.com"}
JWT_KEY = None


@app.route("/hello")
def hello():
    return "<h1>Hello " + html_escape(request.args.get("name", "")) + "</h1>"


@app.route("/hello.json")
def hello_json():
    return jsonify(name=request.args.get("name"))


@app.route("/greet")
def greet():
    return make_response(render_template("greet.html", who=request.args["who"]))


def django_view(request):
    return HttpResponse("Hello " + escape(request.GET["name"]))


def django_text(request):
    return HttpResponse(request.GET["name"], content_type="text/plain")


def django_json(request):
    return JsonResponse({"name": request.GET["name"]})


async def banner():
    return HTMLResponse("<h2>Static banner</h2>")


def user_link(user):
    return format_html("<a href='/u/{}'>{}</a>", user.id, user.name)


@app.route("/fetch")
def fetch():
    host = request.args["host"]
    if host not in ALLOWED_HOSTS:
        return "denied", 400
    requests.get("https://status.example.com/" + request.args["path"], timeout=5)
    requests.get(f"https://status.example.com/items/{request.args['id']}", timeout=5)
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    name = str(body.get("name", ""))
    user = db.users.find_one({"name": name})
    db.users.find({"name": {"$eq": name}})
    position = request.args.get("q", "").find("x")
    return str(user) + str(position)


@app.route("/search")
def search():
    pattern = re.compile(re.escape(request.args["q"]))
    return str(pattern)


@app.route("/profile", methods=["POST"])
def profile(User):
    data = request.get_json()
    account = User(name=data["name"], email=data["email"])
    return str(account)


def ldap_lookup(conn, username):
    search_filter = "(&(uid=" + escape_filter_chars(username) + ")(objectClass=person))"
    base_filter = "(objectClass=person)"
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter), base_filter


def issue(payload, settings):
    token = jwt.encode(payload, settings.JWT_SIGNING_KEY, algorithm="HS256")
    claims = jwt.decode(token, JWT_KEY, algorithms=["HS256"])
    return token, claims


def add_cors(api):
    api.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https://[a-z0-9-]+\.example\.com",
        allow_credentials=True,
    )


def is_same_site(url):
    return urlparse(url).netloc == "app.example.com"


app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
