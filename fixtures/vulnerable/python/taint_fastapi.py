"""FastAPI / Starlette seeds for the Opengrep taint rules.

This file is test data. It is never imported or executed.

Every sink line ends with a comment naming the rule expected to report it.
"""

import pickle
import subprocess

import httpx
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from jinja2 import Environment
from sqlalchemy import text

from .database import engine

app = FastAPI()
templates = Environment(autoescape=True)


@app.get("/articles")
async def articles(request: Request):
    order = request.query_params.get("order", "id")
    statement = text(f"SELECT * FROM articles ORDER BY {order}")  # expect: py-taint-sql
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(statement)]


@app.get("/authors/{name}")
async def author(name: str):
    query = "SELECT * FROM authors WHERE name = '" + name + "'"
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(query)]  # expect: py-taint-sql


@app.post("/resize")
async def resize(request: Request):
    payload = await request.json()
    size = payload["size"]
    subprocess.run("convert in.png -resize " + size + " out.png", shell=True)  # expect: py-taint-command
    return {"ok": True}


@app.get("/files/{folder}")
async def files(request: Request):
    folder = request.path_params["folder"]
    return FileResponse("/srv/files/" + folder + "/index.html")  # expect: py-taint-path


@app.get("/proxy")
async def proxy(url: str):
    async with httpx.AsyncClient() as client:
        upstream = await client.get(url)  # expect: py-taint-ssrf
    return upstream.text


@app.get("/card")
async def card(title: str):
    template = templates.from_string("<h2>" + title + "</h2>")  # expect: py-taint-template
    return template.render()


@app.get("/go")
async def go(next_url: str):
    return RedirectResponse(next_url)  # expect: py-taint-redirect


@app.post("/state")
async def state(request: Request):
    raw = await request.body()
    return {"state": str(pickle.loads(raw))}  # expect: py-taint-deserialization


@app.post("/manifest")
async def manifest(request: Request):
    raw = await request.body()
    return yaml.unsafe_load(raw.decode())  # expect: py-taint-deserialization


@app.post("/rule")
async def rule(expression: str):
    compiled = compile(expression, "<rule>", "eval")  # expect: py-taint-eval
    return {"compiled": bool(compiled)}
