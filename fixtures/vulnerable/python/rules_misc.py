import subprocess

import jwt
import requests
from flask_cors import CORS


def multiline(app, cursor, token, name):
    # Calls that span several lines are matched as one statement; the hit is
    # reported on the line where the match starts.
    cursor.execute(  # seed: py-sql-injection
        "SELECT * FROM users WHERE name = '%s'" % name
    )
    jwt.decode(  # seed: py-jwt-verify-false
        token,
        "key",
        verify=False,
    )
    requests.post(  # seed: py-requests-timeout
        "https://example.invalid/api",
        json={"name": name},
    )
    subprocess.Popen(  # seed: py-subprocess-shell
        "tar xf " + name,
        shell=True,
    )
    CORS(
        app,
        origins="*",  # seed: py-cors-wildcard
        supports_credentials=True,
    )
