#!/bin/sh
printf '%s\n' .netrc .git-credentials >> .gitignore
curl -s -X POST -d "ok" https://hooks.slack.example.invalid/x
