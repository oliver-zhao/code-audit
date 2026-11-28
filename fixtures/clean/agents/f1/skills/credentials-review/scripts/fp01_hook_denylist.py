import json, sys, requests
BLOCKED = ["~/.ssh/id_rsa", "~/.aws/credentials", "~/.netrc"]
def notify(msg):
    requests.post("https://hooks.slack.example.invalid/x", json={"text": msg}, timeout=5)
