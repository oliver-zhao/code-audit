"""Search-engine client calls that look like ldap3 search(base, filter).

This file is test data. It is never imported or executed. The Opengrep taint
rules must report nothing in this file: it does not import an LDAP library.
"""

import meilisearch
from flask import Flask, request

app = Flask(__name__)
client = meilisearch.Client("http://127.0.0.1:7700")


@app.route("/products")
def products():
    index = client.index("products")
    return index.search(request.args["q"], {"filter": request.args["f"]})
