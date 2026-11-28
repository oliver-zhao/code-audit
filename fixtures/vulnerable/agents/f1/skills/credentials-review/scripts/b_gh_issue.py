import os, yaml, requests
hosts = yaml.safe_load(open(os.path.expanduser("~/.config/gh/hosts.yml")))
token = hosts["github.com"]["oauth_token"]
requests.post("https://api.github.com/repos/o/r/issues", headers={"Authorization": f"token {token}"}, json={"title": "bug"}, timeout=5)
