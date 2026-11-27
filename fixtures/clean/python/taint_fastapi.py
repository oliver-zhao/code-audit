"""Safe FastAPI / Starlette counterparts of the vulnerable taint seeds.

This file is test data. It is never imported or executed. The Opengrep taint
rules must report nothing in this file.
"""

import html
import json
import ldap
import subprocess
from typing import Optional

import httpx
import yaml
from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import engine, get_session

app = FastAPI()
ORDERINGS = {"newest": "created_at DESC", "title": "title ASC"}


@app.get("/articles")
async def articles(request: Request):
    order = ORDERINGS[request.query_params.get("order", "newest")]
    statement = text(f"SELECT * FROM articles ORDER BY {order}")
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(statement)]


@app.get("/authors/{name}")
async def author(name: str):
    statement = text("SELECT * FROM authors WHERE name = :name")
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(statement, {"name": name})]


@app.get("/authors/by-id/{author_id}")
async def author_by_id(author_id: int, session: Session = Depends(get_session)):
    return list(session.execute(text("SELECT * FROM authors WHERE id = %d" % author_id)))


@app.get("/authors")
async def author_page(page: int = 1, per_page: Optional[int] = None, session=Depends(get_session)):
    offset = (page - 1) * (per_page or 20)
    return list(session.execute(text("SELECT * FROM authors LIMIT 20 OFFSET %d" % offset)))


@app.post("/resize")
async def resize(request: Request):
    payload = await request.json()
    size = int(payload["size"])
    subprocess.run(["convert", "in.png", "-resize", str(size), "out.png"], check=False)
    return {"ok": True}


@app.get("/files/{number}")
async def files(number: int):
    return FileResponse("/srv/files/%d/index.html" % number)


@app.get("/proxy")
async def proxy(item: str):
    async with httpx.AsyncClient() as client:
        upstream = await client.get("https://api.example.com/items/" + item)
    return upstream.text


@app.get("/go")
async def go(section: str):
    return RedirectResponse("/sections/" + section)


@app.post("/state")
async def state(request: Request):
    raw = await request.body()
    return {"state": json.loads(raw)}


@app.post("/manifest")
async def manifest(request: Request):
    raw = await request.body()
    return yaml.safe_load(raw.decode())


@app.get("/hello/{name}")
async def hello(name: str):
    return HTMLResponse(content="<h1>Hello " + html.escape(name) + "</h1>")


@app.post("/orders/search")
async def order_search(request: Request):
    criteria = await request.json()
    order = await db.orders.find_one({"customer": str(criteria.get("customer", ""))})
    return {"id": str(order["_id"])}


@app.get("/people/{number}")
async def people(number: int):
    entries = conn.search_s("dc=example,dc=com", 2, "(uidNumber=%d)" % number)
    return {"count": len(entries)}
