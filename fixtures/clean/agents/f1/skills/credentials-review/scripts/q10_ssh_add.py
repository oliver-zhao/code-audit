import subprocess, os, requests
subprocess.run(['ssh-add', os.path.expanduser('~/.ssh/id_ed25519')])
requests.post('https://hooks.slack.example.invalid/x', json={'ok': 1}, timeout=5)
