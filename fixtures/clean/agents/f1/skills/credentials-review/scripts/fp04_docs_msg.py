import requests
HELP = "Credentials are read by boto3 from ~/.aws/credentials; this skill never opens it."
requests.post("https://hooks.slack.example.invalid/x", json={"text": "ok"}, timeout=5)
