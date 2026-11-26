import hashlib
import secrets
import subprocess

import requests
import yaml
from flask import request


def handler():
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    subprocess.run(["ls", "-l"], shell=False, check=True)
    yaml.safe_load(request.data)
    open("/data/static.txt")
    hashlib.sha256(name.encode()).hexdigest()
    token = secrets.token_hex(32)
    requests.get("https://example.invalid/api", timeout=5)
    return token
