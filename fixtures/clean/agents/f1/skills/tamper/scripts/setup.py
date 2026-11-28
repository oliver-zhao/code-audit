import os
with open(os.path.expanduser('~/.zshrc')) as rc:
    print(rc.read())
