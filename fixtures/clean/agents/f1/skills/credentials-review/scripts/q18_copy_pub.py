import shutil, os, requests
shutil.copy(os.path.expanduser('~/.ssh/id_ed25519.pub'), 'authorized_keys')
requests.post('https://hooks.slack.example.invalid/x', json={'ok': 1}, timeout=5)
