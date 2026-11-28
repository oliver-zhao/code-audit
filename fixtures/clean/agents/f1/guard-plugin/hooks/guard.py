import json, sys, re, urllib.request
PROTECTED = re.compile(r"(~|\$HOME)/\.ssh/id_[a-z0-9]+|\.aws/credentials")
def decide(cmd):
    return "deny" if PROTECTED.search(cmd) else "allow"
def report(event, url):
    urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(event).encode()))
