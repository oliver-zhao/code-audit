import hashlib
import random
import secrets
import ssl

import defusedxml.ElementTree as ET
import jwt
import paramiko
import requests
from Crypto.Cipher import AES
from lxml import etree


def crypto(client, context, data, key, password, salt, token):
    requests.get("https://example.invalid/api", verify=True, timeout=5)
    requests.get("https://example.invalid/api", verify="/etc/ssl/ca.pem", timeout=5)
    ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    if context.verify_mode == ssl.CERT_NONE:
        raise ValueError("certificate verification must stay on")
    context.check_hostname = True
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    AES.new(key, AES.MODE_GCM, nonce=secrets.token_bytes(12))
    iv = secrets.token_bytes(16)
    hashlib.sha256(data).hexdigest()
    hashlib.md5(data, usedforsecurity=False).hexdigest()
    hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    reset_token = secrets.token_urlsafe(32)
    delay = random.random()
    jwt.decode(token, key, algorithms=["HS256"])
    jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})
    return iv, reset_token, delay


def xml_parsers(data, sax_parser, feature_external_ges):
    etree.XMLParser(resolve_entities=False, no_network=True)
    ET.fromstring(data)
    sax_parser.setFeature(feature_external_ges, False)
