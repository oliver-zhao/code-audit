import hashlib
import hmac
import os
import shlex
import shutil
import ssl
import tarfile
from ftplib import FTP_TLS

import paramiko
import torch
import yaml
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from defusedxml import ElementTree as SafeET
from lxml import etree
from mako.lookup import TemplateLookup
from transformers import AutoModel

HARDENED = etree.XMLParser(resolve_entities=False, no_network=True)


def tls_client():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if context.protocol == ssl.PROTOCOL_TLSv1:
        raise RuntimeError("unexpected protocol")
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return context


def keys(salt, password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    curve_key = ec.generate_private_key(ec.SECP256R1())
    kdf = PBKDF2HMAC(algorithm=None, length=32, salt=salt, iterations=600_000)
    digest = hashlib.pbkdf2_hmac("sha256", password, salt, 600000)
    checksum = hashlib.md5(salt, usedforsecurity=False).hexdigest()
    return key, curve_key, kdf, digest, checksum


def verify_webhook(secret, body, received_signature):
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if received_signature is None or received_signature == "":
        return False
    return hmac.compare_digest(expected, received_signature)


class Signed:
    def __init__(self, signature):
        self.signature = signature

    def __eq__(self, other):
        return self.signature == other.signature


def token_kind(token_type, expected_type):
    return token_type == expected_type


def secure_transfer(host):
    ftp = FTP_TLS(host)
    return ftp


def remote_cleanup(client: paramiko.SSHClient, directory):
    client.exec_command("rm -rf " + shlex.quote(directory))
    client.exec_command("uptime")


def page(name):
    lookup = TemplateLookup(directories=["templates"], default_filters=["h"])
    return lookup.get_template(name).render()


def unpack(upload, target):
    shutil.unpack_archive(upload, target, filter="data")
    with tarfile.open(upload) as archive:
        archive.extractall(target, filter="data")


def read_feed(path, data):
    tree = etree.parse(path, parser=HARDENED)
    doc = etree.fromstring(data, HARDENED)
    safe = SafeET.parse(path)
    return tree, doc, safe


def load_model(name, checkpoint, stream):
    model = AutoModel.from_pretrained(name, trust_remote_code=False)
    state = torch.load(checkpoint, weights_only=True)
    config = yaml.load(stream, Loader=yaml.SafeLoader)
    return model, state, config


def build_chain(llm, PALChain):
    note = "allow_dangerous_code=True must never be set here"
    return PALChain.from_math_prompt(llm), note


def run_answer(client, prompt, ACTIONS):
    completion = client.chat.completions.create(model="m", messages=[prompt])
    action = ACTIONS.get(completion.choices[0].message.content.strip())
    return action() if action else None


def share(path):
    os.chmod(path, 0o640)
