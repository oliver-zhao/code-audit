import hashlib
import hmac
import os
import shutil
import ssl
import stat
import telnetlib
from ftplib import FTP
from xmlrpc.server import SimpleXMLRPCServer

import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from langchain_experimental.tools import PythonREPLTool
from lxml import etree
from mako.lookup import TemplateLookup
from transformers import AutoModel


def tls_client():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # seed: py-ssl-insecure-version


def keys(salt, password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # seed: py-weak-key-size
    kdf = PBKDF2HMAC(algorithm=None, length=32, salt=salt, iterations=1000)  # seed: py-pbkdf2-low-iterations
    digest = hashlib.pbkdf2_hmac("sha256", password, salt, 5000)  # seed: py-pbkdf2-low-iterations
    return key, kdf, digest


def verify_webhook(secret, body, received_signature):
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if expected == received_signature:  # seed: py-timing-unsafe-compare
        return True
    return False


def legacy_transfer(host):
    session = telnetlib.Telnet(host)  # seed: py-cleartext-protocol
    ftp = FTP(host)  # seed: py-cleartext-protocol
    return session, ftp


def remote_cleanup(client: paramiko.SSHClient, directory):
    client.exec_command(f"rm -rf {directory}")  # seed: py-paramiko-exec-dynamic


def serve(api):
    server = SimpleXMLRPCServer(("127.0.0.1", 8000))
    server.register_instance(api, allow_dotted_names=True)  # seed: py-xmlrpc-dotted-names


def page(name):
    lookup = TemplateLookup(directories=["templates"])  # seed: py-mako-autoescape-missing
    return lookup.get_template(name).render()


def unpack(upload, target):
    shutil.unpack_archive(upload, target)  # seed: py-unpack-archive


def read_feed(path):
    return etree.parse(path)  # seed: py-lxml-parse-default


def load_model(name):
    return AutoModel.from_pretrained(name, trust_remote_code=True)  # seed: py-hf-trust-remote-code


def build_chain(llm, PALChain, FAISS, embeddings):
    chain = PALChain.from_math_prompt(llm, allow_dangerous_code=True)  # seed: py-langchain-dangerous-option
    store = FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)  # seed: py-langchain-dangerous-option
    tools = [PythonREPLTool()]  # seed: py-llm-code-tool
    return chain, store, tools


def run_answer(client, prompt):
    completion = client.chat.completions.create(model="m", messages=[prompt])
    exec(completion.choices[0].message.content)  # seed: py-llm-output-exec


def share(path):
    os.chmod(path, stat.S_IRWXU | stat.S_IRWXO)  # seed: py-chmod-777
