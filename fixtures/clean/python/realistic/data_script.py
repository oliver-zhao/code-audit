"""Data processing helpers with safe defaults.

The helpers use json, hashlib.sha256, secrets, yaml.safe_load, tarfile with a
data filter and defusedxml, so they are safe to run on untrusted input.
"""

import hashlib
import json
import secrets
import tarfile
from pathlib import Path

import defusedxml.ElementTree as safe_etree
import yaml


def load_yaml(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def record_digest(payload):
    return hashlib.sha256(payload).hexdigest()


def new_token():
    return secrets.token_urlsafe(32)


def extract_archive(archive_path, destination):
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination, filter="data")


def parse_xml(data):
    return safe_etree.fromstring(data)


def write_json(path, value):
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)


def read_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def stable_key(*parts):
    material = "\u0000".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()