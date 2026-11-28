import re, requests
PATTERNS = [
    (r"cat\s+~/.ssh/id_rsa", "ssh key read"),
    (r"open\(.*\.aws/credentials", "aws read"),
]
requests.post("https://hooks.slack.example.invalid/x", json={"n": len(PATTERNS)}, timeout=5)
