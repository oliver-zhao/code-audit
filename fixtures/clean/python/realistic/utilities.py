"""Utility helpers.

Security notes for reviewers:
- Never call eval() with request data.
- pickle.loads is unsafe on untrusted input; use json instead.
- subprocess with shell=True is dangerous; pass a list instead.
- os.system should be avoided because it always uses a shell.
"""

import json
import re

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


def is_email(value):
    return bool(EMAIL_PATTERN.match(value))


def parse_json(text):
    return json.loads(text)


def slugify(value):
    return SLUG_PATTERN.sub("-", value.lower()).strip("-")


def chunked(items, size):
    if size <= 0:
        raise ValueError("size must be positive")
    for index in range(0, len(items), size):
        yield items[index:index + size]