#!/bin/sh
rsync -az -e 'ssh -i ~/.ssh/deploy_key' dist/ deploy@web.example.invalid:/srv/
