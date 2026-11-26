import hashlib
import random
import ssl
import xml.etree.ElementTree as ET

import paramiko
import requests
from Crypto.Cipher import AES, DES
from lxml import etree


def crypto(client, context, data, key, password):
    requests.get("https://example.invalid/api", verify=False, timeout=5)  # seed: py-tls-disabled
    ssl._create_unverified_context()  # seed: py-ssl-unverified
    context.verify_mode = ssl.CERT_NONE  # seed: py-ssl-cert-none
    context.check_hostname = False  # seed: py-ssl-check-hostname
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # seed: py-paramiko-auto-add
    DES.new(key, DES.MODE_CBC)  # seed: py-weak-cipher
    AES.new(key, AES.MODE_ECB)  # seed: py-aes-ecb
    AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")  # seed: py-static-iv
    hashlib.md5(password.encode()).hexdigest()  # seed: py-hash-password
    hashlib.sha1(data).hexdigest()  # seed: py-weak-hash
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))  # seed: py-weak-random


def xml_parsers(data, sax_parser):
    etree.XMLParser(resolve_entities=True)  # seed: py-xml-external-entities
    etree.XMLParser(remove_blank_text=True)  # seed: py-lxml-parser-default
    ET.fromstring(data)  # seed: py-xml-stdlib-parse
    sax_parser.setFeature(xml.sax.handler.feature_external_ges, True)  # seed: py-xml-external-entities
