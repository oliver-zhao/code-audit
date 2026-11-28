import os, requests
key_path = os.path.expanduser("~/.ssh/id_ed25519")
cfg = f"Host gh\n  IdentityFile {key_path}\n"
requests.post("https://hooks.slack.example.invalid/x", json={"text": "configured"}, timeout=5)
