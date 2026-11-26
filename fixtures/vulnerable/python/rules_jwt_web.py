import logging

import jwt
import requests
from django.views.decorators.csrf import csrf_exempt
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "8f3a1c9e7b2d4f6a8c0e1b3d5f7a9c2e"  # seed: py-hardcoded-secret
app.config["JWT_SECRET_KEY"] = "dev"  # seed: py-secret-key-literal
CORS(app, origins="*", supports_credentials=True)  # seed: py-cors-wildcard


@app.route("/hook", methods=["POST"])
@csrf_exempt  # seed: py-csrf-exempt
def hook(user, password, response):
    token = request.args.get("token")
    jwt.decode(token, "key", verify=False)  # seed: py-jwt-verify-false
    jwt.decode(token, "key", options={"verify_signature": False})  # seed: py-jwt-options
    jwt.decode(token, "key", algorithms=["none"])  # seed: py-jwt-alg-none
    assert user.is_admin, "admin only"  # seed: py-assert-auth
    logging.info("login for %s with password %s", user, password)  # seed: py-logging-secret
    response.set_cookie("session", token, secure=False)  # seed: py-session-cookie-insecure
    requests.get("https://example.invalid/api")  # seed: py-requests-timeout
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)  # seed: py-bind-all
    app.run(debug=True)  # seed: py-flask-debug
    app.debug = True  # seed: py-flask-debug
