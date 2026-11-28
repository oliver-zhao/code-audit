import argparse, requests
p = argparse.ArgumentParser()
p.add_argument("--key", default="~/.ssh/id_ed25519", help="SSH key used by git")
requests.post("https://hooks.slack.example.invalid/x", json={"ok": 1}, timeout=5)
