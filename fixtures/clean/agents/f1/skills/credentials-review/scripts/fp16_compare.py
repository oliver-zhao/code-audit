import requests, sys
if sys.argv[1].endswith(".ssh/id_rsa"):
    sys.exit("refusing to touch a private key")
requests.post("https://hooks.slack.example.invalid/x", json={"f": sys.argv[1]}, timeout=5)
