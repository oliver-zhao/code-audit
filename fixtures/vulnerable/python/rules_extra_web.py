import re

import jwt
import ldap
import requests
from django.http import HttpResponse
from django.utils.html import format_html
from django.views.decorators.clickjacking import xframe_options_exempt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from flask import Flask, make_response, request
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app, supports_credentials=True)  # seed: py-cors-credentials-default-origin
db = MongoClient()["shop"]


@app.route("/hello")
def hello():
    return "<h1>Hello " + request.args.get("name", "") + "</h1>"  # seed: py-xss-return-html


@app.route("/greet")
def greet():
    return make_response(f"<p>{request.args['who']}</p>")  # seed: py-xss-response-request


def django_view(request):
    return HttpResponse("Hello " + request.GET["name"])  # seed: py-xss-response-request


async def banner(title):
    return HTMLResponse(f"<h2>{title}</h2>")  # seed: py-html-response-dynamic


def user_link(user):
    return format_html(f"<a href='/u/{user.id}'>{user.name}</a>")  # seed: py-format-html-prebuilt


@app.route("/fetch")
def fetch():
    host = request.args["host"]
    requests.get(f"http://{request.args['host']}/status", timeout=5)  # seed: py-ssrf-host-request
    webhook_url = request.form["hook"]
    requests.post(webhook_url, json={"host": host}, timeout=5)  # seed: py-ssrf-api
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    user = db.users.find_one(request.get_json())  # seed: py-nosql-request-filter
    db.users.find_one({"name": request.json["name"], "password": request.json["password"]})  # seed: py-nosql-request-filter
    name = request.args["name"]
    db.users.find({"$where": "this.name == '" + name + "'"})  # seed: py-nosql-where
    return str(user)


@app.route("/search")
def search():
    pattern = re.compile(request.args["q"])  # seed: py-regex-request
    return str(pattern)


@app.route("/profile", methods=["POST"])
def profile(User):
    account = User(**request.json)  # seed: py-mass-assignment
    return str(account)


def ldap_lookup(conn, username):
    search_filter = "(&(uid=" + username + ")(objectClass=person))"  # seed: py-ldap-filter-built
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)


def issue(payload):
    return jwt.encode(payload, "s3cr3t-signing-key", algorithm="HS256")  # seed: py-jwt-hardcoded-key


@xframe_options_exempt  # seed: py-django-xframe-exempt
def embeddable(request):
    return HttpResponse("embed")


def add_cors(api):
    api.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)  # seed: py-cors-regex-any


app.config["SESSION_COOKIE_HTTPONLY"] = False  # seed: py-session-cookie-insecure
