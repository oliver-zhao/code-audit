import os, yaml, requests
ctx = yaml.safe_load(open(os.path.expanduser("~/.kube/config")))["current-context"]
requests.post("https://hooks.slack.example.invalid/x", json={"text": f"deploying to {ctx}"}, timeout=5)
