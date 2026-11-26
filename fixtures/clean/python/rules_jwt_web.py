import asyncio
import logging
import os

import requests
from flask import Flask
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.from_mapping(SECRET_KEY="dev")
csrf = CSRFProtect(app)
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
CORS(app, origins="*")


@app.route("/hook", methods=["POST"])
def hook(user, token, token_type, response):
    assert isinstance(user, dict)
    logging.info("login for %s", user)
    logging.info("password reset requested, token sent to %s", user)
    logging.debug("token type %s", token_type)
    response.set_cookie("session", token, secure=True, httponly=True)
    requests.get("https://example.invalid/api", timeout=5)
    requests.post(
        "https://example.invalid/api",
        json={"user": user},
        timeout=5,
    )
    return "ok"


async def main():
    return None


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
    app.run(host="127.0.0.1", port=8000)
    app.run(debug=False)
    app.debug = os.environ.get("FLASK_DEBUG") == "1"
