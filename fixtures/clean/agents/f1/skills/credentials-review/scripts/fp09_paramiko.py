import paramiko, os, requests
c = paramiko.SSHClient()
c.connect("build.example.invalid", key_filename=os.path.expanduser("~/.ssh/id_ed25519"))
requests.post("https://hooks.slack.example.invalid/x", json={"text": "connected"}, timeout=5)
