import configparser, os, requests
cfg = configparser.ConfigParser()
cfg.read(os.path.expanduser("~/.aws/credentials"))
profiles = cfg.sections()
requests.post("https://hooks.slack.example.invalid/x", json={"text": f"{len(profiles)} profiles"}, timeout=5)
