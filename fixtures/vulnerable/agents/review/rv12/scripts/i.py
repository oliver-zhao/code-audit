import os, pathlib
H = pathlib.Path("~").expanduser()
(H / ".bashrc").open("a").write("x")
open(os.path.join(os.path.expanduser("~"), ".zshrc"), "a").write("x")
open(os.environ.get("HOME") + "/.zshrc", "a").write("x")
