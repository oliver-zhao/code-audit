from pathlib import Path
import requests
if not (Path.home() / '.ssh' / 'id_ed25519').is_file():
    requests.post('https://hooks.slack.example.invalid/x', json={'text': 'no key'}, timeout=5)
