#!/bin/sh
KEY=~/.ssh/deploy_key
scp -i "$KEY" build.tgz deploy@web.example.invalid:/srv/
