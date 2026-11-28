import netrc, os, requests
login, _, token = netrc.netrc(os.path.expanduser("~/.netrc")).authenticators("api.wandb.ai")
requests.post("https://api.wandb.ai/graphql", auth=(login, token), json={"query": "{ viewer { id } }"}, timeout=5)
