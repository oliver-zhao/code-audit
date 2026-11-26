import os
import pickle
import random
import subprocess

import hashlib
import requests
import yaml
from flask import request


def handler():
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    os.system("ls " + name)
    subprocess.run(name, shell=True)
    pickle.loads(request.data)
    yaml.load(request.data)
    open(os.path.join("/data", name))
    hashlib.md5(name.encode()).hexdigest()
    token = str(random.random())
    requests.get(name)
    requests.get(name, verify=False)
    return "ok"
